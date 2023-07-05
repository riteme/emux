#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <algorithm>
#include <random>

extern "C" {
#include "ioctl.h"
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "%s [path] [max id] [count]\n", argv[0]);
        return -1;
    }

    const char *path = argv[1];
    size_t max_id = atoll(argv[2]);
    size_t count = atoll(argv[3]);

    int fd = open(path, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "Cannot open \"%s\": errno=%d\n", path, errno);
        return -1;
    }

    auto a = new __u64[max_id];
    for (size_t i = 0; i < max_id; i++) {
        a[i] = i;
    }
    std::shuffle(a, a + max_id, std::mt19937_64(std::random_device{}()));

    emux_ioctl ctl;
    memset(&ctl, 0, sizeof(ctl));
    ctl.op = EMUX_IOCTL_MARK;
    ctl.count = count;
    ctl.ids = a;

    int ret = ioctl(fd, EMUX_IOCTL, &ctl);

    delete[] a;

    if (ret < 0) {
        fprintf(stderr, "Cannot ioctl: errno=%d\n", errno);
        return -1;
    } else {
        printf("#performed= %llu\n", ctl.performed);
    }

    return 0;
}
