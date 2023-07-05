#pragma once

#include <linux/types.h>

enum emux_ioctl_op {
    EMUX_IOCTL_MARK,
    EMUX_IOCTL_RECLAIM,
};

struct emux_ioctl {
    enum emux_ioctl_op op;
    __u64 count;
    const __u64 *ids;
    __u64 performed;
};

// #define EMUX_IOCTL_MAX_COUNT 65536

#define EMUX_IOCTL _IOWR('E', 0, struct emux_ioctl)
