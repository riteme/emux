#pragma once

#include <linux/types.h>

struct emux_ioctl {
    u64 num_to_mark;
    u64 *__user mark_ids;
    u64 marked;

    u64 num_to_reclaim;
    u64 *__user reclaim_ids;
    u64 reclaimed;
};

#define EMUX_IOCTL _IOWR('E', 0, struct emux_ioctl)

#define EMUX_MAX_NUM_IDS 65536
