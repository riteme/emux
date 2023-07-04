#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sstream>

#include <readline/history.h>
#include <readline/readline.h>

extern "C" {
#include "ioctl.h"
}

constexpr size_t page_size = 4096;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "%s [path]\n", argv[0]);
        return -1;
    }

    auto path = argv[1];
    int fd = open(path, O_RDWR | O_DIRECT | O_SYNC);
    if (fd < 0) {
        fprintf(stderr, "Failed to open \"%s\": errno=%d\n", path, errno);
        return -1;
    }

    while (auto line = readline("> ")) {
        add_history(line);

        std::string op;
        std::string filler;
        size_t count;
        size_t start_id;

        std::stringstream ss(line);
        ss >> op;
        if (op == "w")
            ss >> filler >> count >> start_id;
        else
            ss >> count >> start_id;

        size_t size = count * page_size;
        off_t offset = start_id * page_size;

        if (!ss || (op != "r" && op != "w" && op != "m" && op != "c") ||
            (op == "w" && filler.size() != 1) || (size == 0)) {
            puts("r [count] [start id]");
            puts("w [filler char] [count] [start id]");
            puts("m [count] [start id]");
            puts("c [count] [start id]");
        } else if (op == "r" || op == "w") {
            bool is_read = (op == "r");
            const char *op_name = (is_read ? "read" : "write");
            auto buf = (char *)aligned_alloc(page_size, size);
            memset(buf, filler[0], size);

            ssize_t ret;
            if (is_read)
                ret = pread(fd, buf, size, offset);
            else
                ret = pwrite(fd, buf, size, offset);

            if (ret < 0) {
                fprintf(stderr, "Cannot %s: errno=%d\n", op_name, errno);
                continue;
            }

            char c = (is_read ? buf[0] : filler[0]);
            printf("%s %zd of %zu \"%c\" (0x%x)\n", op_name, ret, size, c, c);

            free(buf);
        } else {
            emux_ioctl ctl;
            memset(&ctl, 0, sizeof(ctl));

            if (op == "m")
                ctl.op = EMUX_IOCTL_MARK;
            else
                ctl.op = EMUX_IOCTL_RECLAIM;

            ctl.count = count;
            auto ids = new __u64[count];
            for (__u64 i = 0; i < count; i++) {
                ids[i] = start_id + i;
            }
            ctl.ids = ids;

            int ret = ioctl(fd, EMUX_IOCTL, &ctl);
            if (ret < 0) {
                fprintf(stderr, "Cannot perform ioctl: errno=%d\n", errno);
            }

            delete[] ids;
        }
    }

    close(fd);
    return 0;
}
