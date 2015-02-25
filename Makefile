#
# Makefile for the Linux Traffic Control Unit.
#
KBUILD_CFLAGS += -w
obj-y	:= sch_generic.o sch_mq.o

obj-$(CONFIG_NET_SCHED)		+= sch_api.o sch_blackhole.o
obj-m						+= sch_dyfifo.o
obj-m     += sch_dycbq.o

all:

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:

	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
