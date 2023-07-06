#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <chrono>
#include <random>
#include <vector>

extern "C" {
#include "ioctl.h"
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        fprintf(stderr, "%s [path] [max id] [width] [count]\n", argv[0]);
        return -1;
    }

    const char *path = argv[1];
    size_t max_id = atoll(argv[2]);
    size_t width = atoll(argv[3]);
    size_t count = atoll(argv[4]);

    assert(max_id % width == 0);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Cannot open \"%s\": errno=%d\n", path, errno);
        return -1;
    }

    size_t n = max_id / width;
    std::vector<__u64> a(n);
    for (size_t i = 0; i < n; i++) {
        a[i] = i * width;
    }
    std::shuffle(a.begin(), a.end(), std::mt19937_64(std::random_device{}()));
    a.resize(count);

    std::vector<__u64> b;
    b.reserve(count * width);
    for (size_t i : a) {
        for (size_t j = 0; j < width; j++) {
            b.push_back(i + j);
        }
    }

    emux_ioctl ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.op = EMUX_IOCTL_MARK;
    ctl.count = b.size();
    ctl.ids = b.data();

    auto t0 = std::chrono::steady_clock::now();
    int ret = ioctl(fd, EMUX_IOCTL, &ctl);
    auto t = std::chrono::steady_clock::now() - t0;

    if (ret < 0) {
        fprintf(stderr, "Cannot ioctl: errno=%d\n", errno);
        return -1;
    } else {
        auto time_us = std::chrono::duration_cast<std::chrono::nanoseconds>(t).count() / 1000.0;
        printf("#performed= %llu (%.3lf us)\n", ctl.performed, time_us);
    }

    return 0;
}
