obj-m := dummy_plugin.o
obj-m += cctrack_plugin.o
cctrack_plugin-objs := corny_conntrack_plugin.o cctrack_hash.o cctrack_util.o \
	cctrack_stats.o cctrack_controller.o cctrack_ring_local_storage.o \
	cctrack_stats_generic.o

EXTRA_CFLAGS += -I$(PWD)/.. 
#-Wconversion
KBUILD_EXTRA_SYMBOLS := $(PWD)/../Module.symvers

all:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build SUBDIRS=$(PWD) clean
