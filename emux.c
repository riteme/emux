// Adapted from drivers/md/dm-switch.c, Linux 6.2.1

/*
 * Copyright (C) 2010-2012 by Dell Inc.  All rights reserved.
 * Copyright (C) 2011-2013 Red Hat, Inc.
 *
 * This file is released under the GPL.
 *
 * dm-switch is a device-mapper target that maps IO to underlying block
 * devices efficiently when there are a large number of fixed-sized
 * address regions but there is no simple pattern to allow for a compact
 * mapping representation such as dm-stripe.
 */

#include <linux/device-mapper.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/vmalloc.h>

#include "ioctl.h"

#define MODULE_NAME   "emux"
#define DM_MSG_PREFIX MODULE_NAME
#define LOWER_DEVICE  0
#define UPPER_DEVICE  1

/*
 * A device with the offset to its start sector.
 */
struct switch_path {
    struct dm_dev *dmdev;
    sector_t start;
};

enum emux_page_state {
    EMUX_PAGE_UNCACHED = 0,
    EMUX_PAGE_PENDING,
    EMUX_PAGE_PROMOTING,
    EMUX_PAGE_CACHED,
};

static const char *emux_page_state_name[] = {
    [EMUX_PAGE_UNCACHED] = "uncached",
    [EMUX_PAGE_PENDING] = "pending",
    [EMUX_PAGE_PROMOTING] = "promoting",
    [EMUX_PAGE_CACHED] = "cached",
};

struct emux_page {
    struct mutex mutex;
    union {
        const enum emux_page_state state;
        enum emux_page_state __state_writable;
    };
    u32 version;
    u64 id;
    u8 pad[16];  // Align to 64 bytes, i.e. one cache line
};

// We use a wrapper function to ease debug logging
static __always_inline void emux_set_page_state(struct emux_page *page,
                                                enum emux_page_state state) {
    DMINFO("page #%llu (v%u): \"%s\" -> \"%s\"",
           page->id,
           page->version,
           emux_page_state_name[page->state],
           emux_page_state_name[state]);
    page->__state_writable = state;
}

struct emux_ctx {
    u64 page_sectors;  // Page size in sectors, e.g. 8 for 4k page size
    u64 num_pages;
    struct switch_path *paths;
    struct bio_set bioset;

    // Device mapper does not provide callback for ioctl. It only allows dm targets
    // to redirect a ioctl request to an underlying block device. Therefore we use a
    // fake block device to receive the ioctl request. This method does not modify
    // device mapper source code.
    struct block_device fake_dev;

    // Page metadata
    struct emux_page pages[];
};

static u64
emux_handle_mark_or_reclaim(struct emux_ctx *emux, u64 *ids, u64 count, enum emux_ioctl_op op) {
    u64 performed = 0, i, id;
    struct emux_page *page;

    for (i = 0; i < count; i++) {
        id = ids[i];
        if (id > emux->num_pages)
            continue;

        page = &emux->pages[id];
        mutex_lock(&page->mutex);

        switch (op) {
            case EMUX_IOCTL_MARK: {
                if (page->state == EMUX_PAGE_UNCACHED) {
                    emux_set_page_state(page, EMUX_PAGE_PENDING);
                }
            } break;

            case EMUX_IOCTL_RECLAIM: {
                if (page->state != EMUX_PAGE_UNCACHED) {
                    emux_set_page_state(page, EMUX_PAGE_UNCACHED);
                    page->version++;
                }
            }
        }

        mutex_unlock(&page->mutex);

        performed++;
    }

    return performed;
}

static int emux_handle_ioctl(struct emux_ctx *emux, struct emux_ioctl *__user uargs) {
    struct emux_ioctl args;
    u64 *ids;
    int ret = 0;

    if (copy_from_user(&args, uargs, sizeof(args)))
        return -EFAULT;
    switch (args.op) {
        case EMUX_IOCTL_MARK:
        case EMUX_IOCTL_RECLAIM: break;

        default: return -EINVAL;
    }
    if (args.count > EMUX_IOCTL_MAX_COUNT)
        return -EINVAL;
    if (args.performed != 0)
        return -EINVAL;

    if (args.count == 0)
        return 0;

    ids = vcalloc(args.count, sizeof(ids[0]));
    if (!ids)
        return -ENOMEM;

    if (copy_from_user(ids, args.ids, array_size(args.count, sizeof(ids[0])))) {
        ret = -EFAULT;
        goto err;
    }

    args.performed = emux_handle_mark_or_reclaim(emux, ids, args.count, args.op);

    if (copy_to_user(&uargs->performed, &args.performed, sizeof(args.performed))) {
        ret = -EFAULT;
        goto err;
    }

err:
    vfree(ids);
    return ret;
}

static int emux_ioctl(struct block_device *bdev, fmode_t mode, unsigned cmd, unsigned long arg) {
    struct emux_ctx *emux = container_of(bdev, struct emux_ctx, fake_dev);
    struct block_device *lower_dev = emux->paths[LOWER_DEVICE].dmdev->bdev;

    if (cmd == EMUX_IOCTL)
        return emux_handle_ioctl(emux, (struct emux_ioctl *)arg);
    else
        return lower_dev->bd_disk->fops->ioctl(lower_dev, mode, cmd, arg);
}

static struct block_device_operations emux_fops = {
    .ioctl = emux_ioctl,
};

static struct gendisk emux_fake_disk = {
    .fops = &emux_fops,
};

static struct emux_ctx *emux_alloc_ctx(u64 page_sectors, u64 num_pages, struct switch_path *paths) {
    u64 i;
    struct emux_ctx *emux;

    emux = vzalloc(struct_size(emux, pages, num_pages));
    if (!emux)
        goto err_alloc_ctx;

    if (bioset_init(&emux->bioset, BIO_POOL_SIZE, 0, 0))
        goto err_bioset_init;

    emux->page_sectors = page_sectors;
    emux->num_pages = num_pages;
    emux->paths = paths;
    emux->fake_dev.bd_disk = &emux_fake_disk;
    for (i = 0; i < num_pages; i++) {
        mutex_init(&emux->pages[i].mutex);
        emux->pages[i].id = i;
    }

    return emux;

err_bioset_init:
    vfree(emux);
err_alloc_ctx:
    return NULL;
}

static void emux_free_ctx(struct emux_ctx *emux) {
    bioset_exit(&emux->bioset);
    vfree(emux);
}

struct emux_promotion {
    void *old_bi_private;
    bio_end_io_t *old_bi_end_io;
    struct emux_ctx *emux;
    struct emux_page *page;
    u32 version;
};

/*
 * Context block for a dm switch device.
 */
struct switch_ctx {
    struct dm_target *ti;
    unsigned nr_paths; /* Number of paths in path_list. */

    struct emux_ctx *emux;

    /*
	 * Array of dm devices to switch between.
	 */
    struct switch_path path_list[];
};

static struct switch_ctx *alloc_switch_ctx(struct dm_target *ti, unsigned nr_paths) {
    struct switch_ctx *sctx;

    sctx = kzalloc(struct_size(sctx, path_list, nr_paths), GFP_KERNEL);
    if (!sctx)
        return NULL;

    sctx->ti = ti;

    ti->private = sctx;

    return sctx;
}

static int parse_path(struct dm_arg_set *as, struct dm_target *ti) {
    struct switch_ctx *sctx = ti->private;
    struct dm_dev **dev_p = &sctx->path_list[sctx->nr_paths].dmdev;
    unsigned long long start;
    int r;

    r = dm_get_device(ti, dm_shift_arg(as), dm_table_get_mode(ti->table), dev_p);
    if (r) {
        ti->error = "Device lookup failed";
        return r;
    }

    if (kstrtoull(dm_shift_arg(as), 10, &start) || start != (sector_t)start) {
        ti->error = "Invalid device starting offset";
        dm_put_device(ti, *dev_p);
        return -EINVAL;
    }

    if (start != 0) {
        ti->error = "Start sector must be zero";
        dm_put_device(ti, *dev_p);
        return -EINVAL;
    }
    if ((*dev_p)->bdev->bd_nr_sectors < ti->len) {
        ti->error = "Block device is smaller than expected";
        dm_put_device(ti, *dev_p);
        return -EINVAL;
    }

    sctx->path_list[sctx->nr_paths].start = start;

    sctx->nr_paths++;

    return 0;
}

/*
 * Destructor: Don't free the dm_target, just the ti->private data (if any).
 */
static void switch_dtr(struct dm_target *ti) {
    struct switch_ctx *sctx = ti->private;

    while (sctx->nr_paths--)
        dm_put_device(ti, sctx->path_list[sctx->nr_paths].dmdev);

    emux_free_ctx(sctx->emux);

    kfree(sctx);
}

/*
 * Constructor arguments:
 *   <num_paths> <region_size> <num_optional_args> [<optional_args>...]
 *   [<dev_path> <offset>]+
 *
 * Optional args are to allow for future extension: currently this
 * parameter must be 0.
 */
static int switch_ctr(struct dm_target *ti, unsigned argc, char **argv) {
    static const struct dm_arg _args[] = {
        {1,
         (KMALLOC_MAX_SIZE - sizeof(struct switch_ctx)) / sizeof(struct switch_path),
         "Invalid number of paths"},
        {1, UINT_MAX, "Invalid region size"},
        {0, 0, "Invalid number of optional args"},
    };

    struct switch_ctx *sctx;
    struct dm_arg_set as;
    unsigned nr_paths, region_size, nr_optional_args;
    int r;
    u64 num_pages;

    as.argc = argc;
    as.argv = argv;

    r = dm_read_arg(_args, &as, &nr_paths, &ti->error);
    if (r)
        return -EINVAL;

    if (nr_paths != 2) {
        ti->error = "EMux needs exactly two backing devices";
        return -EINVAL;
    }
    if (ti->begin != 0) {
        ti->error = "Offset must be zero";
        return -EINVAL;
    }

    r = dm_read_arg(_args + 1, &as, &region_size, &ti->error);
    if (r)
        return r;

    r = dm_read_arg_group(_args + 2, &as, &nr_optional_args, &ti->error);
    if (r)
        return r;
    /* parse optional arguments here, if we add any */

    if (as.argc != nr_paths * 2) {
        ti->error = "Incorrect number of path arguments";
        return -EINVAL;
    }

    sctx = alloc_switch_ctx(ti, nr_paths);
    if (!sctx) {
        ti->error = "Cannot allocate redirection context";
        return -ENOMEM;
    }

    r = dm_set_target_max_io_len(ti, region_size);
    if (r)
        goto error;

    num_pages = DIV_ROUND_UP(ti->len, region_size);
    sctx->emux = emux_alloc_ctx(region_size, num_pages, sctx->path_list);
    if (!sctx->emux) {
        ti->error = "Cannot allocate EMux context";
        r = -ENOMEM;
        goto error;
    }
    DMINFO("Allocated EMux context for %llu pages", num_pages);

    while (as.argc) {
        r = parse_path(&as, ti);
        if (r)
            goto error;
    }

    /* For UNMAP, sending the request down any path is sufficient */
    ti->num_discard_bios = 1;

    return 0;

error:
    switch_dtr(ti);

    return r;
}

static void emux_map_bio(struct emux_ctx *emux, struct bio *bio, u64 path_id) {
    struct switch_path *path = &emux->paths[path_id];
    bio_set_dev(bio, path->dmdev->bdev);
}

static void emux_clone_and_map_bio(struct emux_ctx *emux, struct bio *bio) {
    struct bio *new_bio;

    emux_map_bio(emux, bio, LOWER_DEVICE);

    new_bio = bio_alloc_clone(NULL, bio, GFP_NOIO, &emux->bioset);
    BUG_ON(!new_bio);

    emux_map_bio(emux, new_bio, UPPER_DEVICE);
    bio_chain(new_bio, bio);
    submit_bio(new_bio);
}

static void emux_promotion_done(struct bio *bio) {
    bio_free_pages(bio);
}

static bool emux_start_promotion(struct emux_ctx *emux, struct bio *bio) {
    u32 vcnt = bio_segments(bio);
    struct bio *new_bio;
    struct bvec_iter iter;
    struct bio_vec bv;
    struct page *page;

    BUG_ON(bio_op(bio) != REQ_OP_READ);

    new_bio = bio_alloc_bioset(NULL, vcnt, REQ_OP_WRITE, GFP_NOIO, &emux->bioset);
    goto err_bio_alloc;

    bio_for_each_segment(bv, bio, iter) {
        page = alloc_pages(GFP_NOIO, get_order(bv.bv_len));
        if (!page)
            goto err_alloc_pages;

        bio_add_page(bio, page, bv.bv_len, 0);
    }

    bio_copy_data(new_bio, bio);
    emux_map_bio(emux, bio, UPPER_DEVICE);
    new_bio->bi_end_io = emux_promotion_done;
    submit_bio(new_bio);
    return true;

err_alloc_pages:
    bio_free_pages(new_bio);
    bio_put(bio);
err_bio_alloc:
    return false;
}

static void emux_promote(struct bio *bio) {
    struct emux_promotion *promote = bio->bi_private;
    struct emux_page *page = promote->page;

    mutex_lock(&page->mutex);
    if (page->version == promote->version && page->state == EMUX_PAGE_PROMOTING) {
        if (emux_start_promotion(promote->emux, bio)) {
            emux_set_page_state(page, EMUX_PAGE_CACHED);
        } else {
            // Promotion of this time is failed. Maybe the next time will succeed
            emux_set_page_state(page, EMUX_PAGE_PENDING);
        }
    }
    mutex_unlock(&page->mutex);

    bio->bi_private = promote->old_bi_private;
    bio->bi_end_io = promote->old_bi_end_io;
    kfree(promote);

    bio->bi_end_io(bio);
}

static bool
emux_wrap_bio_with_promotion(struct emux_ctx *emux, struct bio *bio, struct emux_page *page) {
    struct emux_promotion *promote = kzalloc(sizeof(*promote), GFP_NOIO);
    if (!promote)
        return false;

    promote->old_bi_private = bio->bi_private;
    promote->old_bi_end_io = bio->bi_end_io;
    promote->emux = emux;
    promote->page = page;
    promote->version = page->version;

    bio->bi_private = promote;
    bio->bi_end_io = emux_promote;

    return true;
}

static int
emux_map_rw_locked(struct emux_ctx *emux, struct bio *bio, struct emux_page *page, bool write) {
    switch (page->state) {
        case EMUX_PAGE_UNCACHED: {
            emux_map_bio(emux, bio, LOWER_DEVICE);
        } break;

        case EMUX_PAGE_PENDING: {
            if (write) {
                emux_clone_and_map_bio(emux, bio);
                emux_set_page_state(page, EMUX_PAGE_CACHED);
            } else {
                emux_map_bio(emux, bio, LOWER_DEVICE);
                if (emux_wrap_bio_with_promotion(emux, bio, page))
                    emux_set_page_state(page, EMUX_PAGE_PROMOTING);
            }
        } break;

        case EMUX_PAGE_PROMOTING: {
            if (write) {
                emux_clone_and_map_bio(emux, bio);
                emux_set_page_state(page, EMUX_PAGE_CACHED);
            } else {
                emux_map_bio(emux, bio, LOWER_DEVICE);
            }
        } break;

        case EMUX_PAGE_CACHED: {
            if (write)
                emux_clone_and_map_bio(emux, bio);
            else
                emux_map_bio(emux, bio, UPPER_DEVICE);
        } break;
    }

    return DM_MAPIO_REMAPPED;
}

static int emux_map(struct emux_ctx *emux, struct bio *bio) {
    sector_t offset = bio->bi_iter.bi_sector;
    u64 page_id = offset / emux->page_sectors;
    struct emux_page *page = &emux->pages[page_id];
    enum req_op op = bio_op(bio);
    int ret;

    DMINFO("op= %d offset= 0x%llx page #%llu", op, offset * SECTOR_SIZE, page_id);

    switch (op) {
        case REQ_OP_READ:
        case REQ_OP_WRITE:
        case REQ_OP_WRITE_ZEROES: {
            mutex_lock(&page->mutex);
            ret = emux_map_rw_locked(emux, bio, page, bio_data_dir(bio));
            mutex_unlock(&page->mutex);
        } break;

        // All other operations are mapped to lower device
        default: {
            emux_map_bio(emux, bio, LOWER_DEVICE);
            ret = DM_MAPIO_REMAPPED;
        }
    }

    return ret;
}

static int switch_map(struct dm_target *ti, struct bio *bio) {
    struct switch_ctx *sctx = ti->private;
    return emux_map(sctx->emux, bio);
}

static void switch_status(struct dm_target *ti,
                          status_type_t type,
                          unsigned status_flags,
                          char *result,
                          unsigned maxlen) {
    struct switch_ctx *sctx = ti->private;
    unsigned sz = 0;
    int path_nr;

    switch (type) {
        case STATUSTYPE_INFO: result[0] = '\0'; break;

        case STATUSTYPE_TABLE:
            DMEMIT("%u %llu 0", sctx->nr_paths, sctx->emux->page_sectors);
            for (path_nr = 0; path_nr < sctx->nr_paths; path_nr++)
                DMEMIT(" %s %llu",
                       sctx->path_list[path_nr].dmdev->name,
                       (unsigned long long)sctx->path_list[path_nr].start);
            break;

        case STATUSTYPE_IMA: result[0] = '\0'; break;
    }
}

/*
 * Switch ioctl:
 *
 * Passthrough all ioctls to the fake device of EMux
 */
static int switch_prepare_ioctl(struct dm_target *ti, struct block_device **bdev) {
    struct switch_ctx *sctx = ti->private;
    *bdev = &sctx->emux->fake_dev;
    return 0;
}

static int switch_iterate_devices(struct dm_target *ti, iterate_devices_callout_fn fn, void *data) {
    struct switch_ctx *sctx = ti->private;
    int path_nr;
    int r;

    for (path_nr = 0; path_nr < sctx->nr_paths; path_nr++) {
        r = fn(ti, sctx->path_list[path_nr].dmdev, sctx->path_list[path_nr].start, ti->len, data);
        if (r)
            return r;
    }

    return 0;
}

static struct target_type switch_target = {
    .name = MODULE_NAME,
    .version = {0, 1, 0},
    .features = DM_TARGET_NOWAIT,
    .module = THIS_MODULE,
    .ctr = switch_ctr,
    .dtr = switch_dtr,
    .map = switch_map,
    .status = switch_status,
    .prepare_ioctl = switch_prepare_ioctl,
    .iterate_devices = switch_iterate_devices,
};

static int __init dm_switch_init(void) {
    int r;

    r = dm_register_target(&switch_target);
    if (r < 0)
        DMERR("dm_register_target() failed %d", r);

    return r;
}

static void __exit dm_switch_exit(void) {
    dm_unregister_target(&switch_target);
}

module_init(dm_switch_init);
module_exit(dm_switch_exit);

MODULE_DESCRIPTION(DM_NAME " dynamic path switching target");
MODULE_AUTHOR("Kevin D. O'Kelley <Kevin_OKelley@dell.com>");
MODULE_AUTHOR("Narendran Ganapathy <Narendran_Ganapathy@dell.com>");
MODULE_AUTHOR("Jim Ramsay <Jim_Ramsay@dell.com>");
MODULE_AUTHOR("Mikulas Patocka <mpatocka@redhat.com>");
MODULE_LICENSE("GPL");

MODULE_DESCRIPTION("Elastic Multiplexer (EMux)");
MODULE_AUTHOR("Xue Zhenliang <riteme@qq.com>");
