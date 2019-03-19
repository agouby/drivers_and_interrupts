obj-m += main.o

RET=$(shell lsmod | grep main > /dev/null ; echo $$?)

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	make clean
	make
	dmesg -C
ifeq ($(RET),0)
	rmmod main
endif
	insmod main.ko
