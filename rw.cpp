#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <sstream>

#include <readline/history.h>
#include <readline/readline.h>

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
        size_t size;
        off_t offset;

        std::stringstream ss(line);
        ss >> op;
        if (op[0] == 'r')
            ss >> size >> offset;
        else
            ss >> filler >> size >> offset;

        size *= page_size;
        offset *= page_size;

        if (!ss || (op != "r" && op != "w") || (op == "w" && filler.size() != 1) || (size == 0)) {
            puts("r [page count] [page index]");
            puts("w [filler char] [page count] [page index]");
        } else {
            bool is_read = op[0] == 'r';
            const char *op_name = (is_read ? "read" : "write");
            auto buf = (char *)aligned_alloc(page_size, size);
            memset(buf, filler[0], size);

            ssize_t ret;
            if (is_read)
                ret = pread(fd, buf, size, offset);
            else
                ret = pwrite(fd, buf, size, offset);

            if (ret < 0) {
                fprintf(stderr, "Failed to perform %s: errno=%d\n", op_name, errno);
                return -1;
            }

            char c = (is_read ? buf[0] : filler[0]);
            printf("%s %zd of %zu \"%c\" (0x%x)\n", op_name, ret, size, c, c);

            free(buf);
        }
    }

    close(fd);
    return 0;
}
