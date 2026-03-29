ccflags-y += $(MODULE_FLAGS)

ifneq ($(CONFIG_MT76XX_COMBO_DUAL_DRIVER_SUPPORT), )
  MODULE_NAME=mt7915_mtk_warp_proxy
else
  MODULE_NAME=mtk_warp_proxy
endif

CHIP_DIR=chips

OBJS:= warp_proxy.o
#OBJS += $(CHIP_DIR)/warp_wifi_mt7615.o
OBJS += $(CHIP_DIR)/warp_wifi_mt7915.o

#######################################
# For integrating to kernel source
######################################
obj-m += $(MODULE_NAME).o


$(MODULE_NAME)-objs += $(OBJS)

install:

clean:
	rm -rf *.o *.ko *.modules .*.cmd .*.o *.order $(MODULE_NAME).mod.c
