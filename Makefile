obj-m += emux.o

TARGETS = disk rw rand_mark

READLINE_FLAGS = $(shell pkg-config --libs --cflags readline)

.PHONY: all module clean

all: module $(TARGETS)

module:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

disk:
	dd if=/dev/zero of=$@ oflag=direct bs=1M count=2048 status=progress

rw: rw.cpp ioctl.h
	$(CXX) $< $(READLINE_FLAGS) -o $@

rand_mark: rand_mark.cpp ioctl.h
	$(CXX) $< -o $@

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	$(RM) rw $(TARGETS)
