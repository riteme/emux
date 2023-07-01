obj-m += emux.o

READLINE_FLAGS = $(shell pkg-config --libs --cflags readline)

.PHONY: all module clean

all: module disk rw

module:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

disk:
	dd if=/dev/zero of=$@ oflag=direct bs=1M count=2048 status=progress

rw: rw.cpp
	$(CXX) $^ $(READLINE_FLAGS) -o $@

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
