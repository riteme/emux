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
#include <linux/workqueue.h>

#include "ioctl.h"

#define MODULE_NAME      "emux"
#define DM_MSG_PREFIX    MODULE_NAME
#define LOWER_DEVICE     0
#define UPPER_DEVICE     1
#define NUM_RESERVED_BIO 128

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

static __always_unused const char *emux_page_state_name[] = {
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
    // DMINFO("page #%llu (v%u): \"%s\" -> \"%s\"",
    //        page->id,
    //        page->version,
    //        emux_page_state_name[page->state],
    //        emux_page_state_name[state]);

    page->__state_writable = state;
}

struct emux_ctx {
    u64 page_sectors;  // Page size in sectors, e.g. 8 for 4k page size
    u64 page_size;     // == page_sectors * SECTOR_SIZE
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

struct emux_saved_bio {
    void *bi_private;
    void *bi_end_io;
    struct bvec_iter bi_iter;
};

static __always_inline void emux_save_bio(struct emux_saved_bio *save, struct bio *bio) {
    save->bi_private = bio->bi_private;
    save->bi_end_io = bio->bi_end_io;
    save->bi_iter = bio->bi_iter;
}

struct emux_io_action {
    bool map_to_lower : 1;
    bool map_to_upper : 1;
    bool promote : 1;
    u8 version : 5;
};

#define EMUX_PAGE_VERSION_MASK ((1 << 5) - 1)

static __always_inline bool emux_page_promoting(struct emux_page *page,
                                                struct emux_io_action *action) {
    return (page->version & EMUX_PAGE_VERSION_MASK) == action->version &&
           page->state == EMUX_PAGE_PROMOTING;
}

struct emux_io {
    struct emux_ctx *emux;
    struct emux_saved_bio save;
    struct work_struct work;
    struct bio *completed_bio;

    u64 midpart_beg;
    u64 midpart_end;
    u64 start_id;
    struct emux_io_action actions[];
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
    // if (args.count > EMUX_IOCTL_MAX_COUNT)
    //     return -EINVAL;
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

    if (bioset_init(&emux->bioset, NUM_RESERVED_BIO, 0, BIOSET_NEED_BVECS | BIOSET_PERCPU_CACHE))
        goto err_bioset_init;

    emux->page_sectors = page_sectors;
    emux->page_size = page_sectors * SECTOR_SIZE;
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

    // r = dm_set_target_max_io_len(ti, region_size);
    // if (r)
    //     goto error;

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

static __always_unused void emux_print_iter(const char *name, struct bvec_iter iter) {
    DMINFO("%s={sector=%llu, size=%u, idx=%u, done=%u}",
           name,
           iter.bi_sector,
           iter.bi_size,
           iter.bi_idx,
           iter.bi_bvec_done);
}

static struct emux_io_action
emux_map_page_locked(struct emux_ctx *emux, struct emux_page *page, bool write) {
    struct emux_io_action ret = {};

    switch (page->state) {
        case EMUX_PAGE_UNCACHED: {
            ret.map_to_lower = true;
        } break;

        case EMUX_PAGE_PENDING: {
            if (write) {
                ret.map_to_lower = true;
                ret.map_to_upper = true;
                emux_set_page_state(page, EMUX_PAGE_CACHED);
            } else {
                ret.map_to_lower = true;
                ret.promote = true;
                ret.version = page->version;
                emux_set_page_state(page, EMUX_PAGE_PROMOTING);
            }
        } break;

        case EMUX_PAGE_PROMOTING: {
            if (write) {
                ret.map_to_lower = true;
                ret.map_to_upper = true;
                emux_set_page_state(page, EMUX_PAGE_CACHED);
            } else {
                ret.map_to_lower = true;
            }
        } break;

        case EMUX_PAGE_CACHED: {
            if (write) {
                ret.map_to_lower = true;
                ret.map_to_upper = true;
            } else {
                ret.map_to_upper = true;
            }
        } break;
    }

    return ret;
}

static struct emux_io_action
emux_map_page(struct emux_ctx *emux, struct emux_page *page, enum req_op op) {
    struct emux_io_action ret = {};

    switch (op) {
        case REQ_OP_READ:
        case REQ_OP_WRITE:
        case REQ_OP_WRITE_ZEROES: {
            mutex_lock(&page->mutex);

            // DMINFO("op= %d offset= 0x%llx size=%u page #%llu \"%s\"",
            //        op,
            //        offset * SECTOR_SIZE,
            //        bio->bi_iter.bi_size,
            //        page_id,
            //        emux_page_state_name[page->state]);

            ret = emux_map_page_locked(emux, page, (op != REQ_OP_READ));

            mutex_unlock(&page->mutex);
        } break;

        // All other operations are mapped to lower device
        default: {
            DMINFO("unexpected op= %d at page #%llu", op, page->id);
            ret.map_to_lower = true;
        }
    }

    return ret;
}

static void emux_promotion_end_io(struct bio *completed_bio) {
    bio_free_pages(completed_bio);
}

static void
emux_promotion_iterate(struct emux_io *io, struct bio *completed_bio, struct bvec_iter iter) {
    u64 i;

    for (i = io->midpart_beg; i < io->midpart_end; i++) {
        struct emux_page *page = io->emux->pages + io->start_id + i;
        struct bvec_iter page_iter = {
            .bi_sector = page->id * io->emux->page_sectors,
            .bi_size = io->emux->page_size,
        };
        struct bio *new_bio;
        struct page *buf_page;

        if (!io->actions[i].promote) {
            bio_advance_iter(completed_bio, &iter, io->emux->page_size);
            continue;
        }

        mutex_lock(&page->mutex);

        if (emux_page_promoting(page, io->actions + i)) {
            new_bio = bio_alloc_bioset(NULL, 1, REQ_OP_WRITE, GFP_NOIO, &io->emux->bioset);
            BUG_ON(!new_bio);

            buf_page = alloc_pages(GFP_NOIO, get_order(io->emux->page_size));
            BUG_ON(!buf_page);

            bio_add_page(new_bio, buf_page, io->emux->page_size, 0);
            new_bio->bi_iter = page_iter;
            bio_copy_data_iter(new_bio, &page_iter, completed_bio, &iter);

            new_bio->bi_end_io = emux_promotion_end_io;
            emux_map_bio(io->emux, new_bio, UPPER_DEVICE);
            submit_bio(new_bio);

            emux_set_page_state(page, EMUX_PAGE_CACHED);
        } else {
            bio_advance_iter(completed_bio, &iter, io->emux->page_size);
            emux_set_page_state(page, EMUX_PAGE_PENDING);
        }

        mutex_unlock(&page->mutex);
    }
}

static void emux_end_io_handler(struct work_struct *work) {
    struct emux_io *io = container_of(work, struct emux_io, work);
    struct bio *completed_bio = io->completed_bio;

    BUG_ON(completed_bio->bi_status != BLK_STS_OK);

    emux_promotion_iterate(io, completed_bio, io->save.bi_iter);

    completed_bio->bi_private = io->save.bi_private;
    completed_bio->bi_end_io = io->save.bi_end_io;

    if (completed_bio->bi_end_io)
        completed_bio->bi_end_io(completed_bio);

    bio_put(completed_bio);
    kfree(io);
}

static void emux_end_io(struct bio *completed_bio) {
    struct emux_io *io = completed_bio->bi_private;
    schedule_work(&io->work);
}

static int emux_map(struct emux_ctx *emux, struct bio *bio) {
    sector_t offset = bio->bi_iter.bi_sector;
    u64 start_id = offset / emux->page_sectors;
    u64 size = bio->bi_iter.bi_size;
    u64 count = size / emux->page_size;
    u64 beg = 0, end = count, i;
    enum req_op op = bio_op(bio);
    struct emux_io *io;
    bool need_promote = false;

    BUG_ON(offset % emux->page_sectors != 0 || size % emux->page_size != 0);

    io = kzalloc(struct_size(io, actions, count), GFP_NOIO);
    BUG_ON(!io);

    for (i = 0; i < count; i++) {
        io->actions[i] = emux_map_page(emux, &emux->pages[start_id + i], op);
        need_promote |= io->actions[i].promote;
    }

    // Bio is split into at most three parts: left, middle, right
    // left and right parts are not mapped to lower device, so they must be mapped to upper device
    while (beg < end && !io->actions[beg].map_to_lower) {
        beg++;
    }
    while (beg < end && !io->actions[end - 1].map_to_lower) {
        end--;
    }

    // The entire bio is cached
    if (beg >= count) {
        emux_map_bio(emux, bio, UPPER_DEVICE);
        goto out;
    }

    // The left part
    if (beg > 0) {
        struct bio *new_bio = bio_split(bio, beg * emux->page_sectors, GFP_NOIO, &emux->bioset);
        BUG_ON(!new_bio);
        bio_chain(new_bio, bio);
        emux_map_bio(emux, new_bio, UPPER_DEVICE);
        submit_bio(new_bio);
    }

    // The right part
    if (end < count) {
        sector_t mid_sectors = (end - beg) * emux->page_sectors;
        sector_t right_sectors = (count - end) * emux->page_sectors;
        struct bio *new_bio = bio_alloc_clone(NULL, bio, GFP_NOIO, &emux->bioset);
        BUG_ON(!new_bio);
        bio_trim(bio, 0, mid_sectors);
        bio_trim(new_bio, mid_sectors, right_sectors);
        bio_chain(new_bio, bio);
        emux_map_bio(emux, new_bio, UPPER_DEVICE);
        submit_bio(new_bio);
    }

    // Finally the middle part
    // For write requests, map_to_lower is always true
    // For read requests, we always map it to lower device even if map_to_upper is true, since
    // EMux acts as a write-through cache
    emux_map_bio(emux, bio, LOWER_DEVICE);

    if (op == REQ_OP_WRITE || op == REQ_OP_WRITE_ZEROES) {
        for (i = beg; i < end; i++) {
            if (io->actions[i].map_to_upper) {
                struct bio *new_bio = bio_alloc_clone(NULL, bio, GFP_NOIO, &emux->bioset);
                BUG_ON(!new_bio);
                bio_trim(new_bio, (i - beg) * emux->page_sectors, emux->page_sectors);
                bio_chain(new_bio, bio);
                emux_map_bio(emux, new_bio, UPPER_DEVICE);
                submit_bio(new_bio);
            }
        }
    }

out:
    // Install callback if promotion is needed
    if (need_promote) {
        io->emux = emux;
        io->start_id = start_id;
        io->midpart_beg = beg;
        io->midpart_end = end;

        emux_save_bio(&io->save, bio);
        bio->bi_private = io;
        bio->bi_end_io = emux_end_io;

        bio_get(bio);  // To be put in emux_end_io_handler
        io->completed_bio = bio;
        INIT_WORK(&io->work, emux_end_io_handler);

        // io will be freed in emux_end_io_handler
    } else {
        kfree(io);
    }

    return DM_MAPIO_REMAPPED;
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
