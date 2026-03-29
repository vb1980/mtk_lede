ifeq ($(DUAL_KO),YES)
CFLAGS += -DCONFIG_MT76XX_COMBO_DUAL_DRIVER_SUPPORT
endif

all:
	gcc $(CFLAGS) -g bin2h.c -o bin2h
clean:
	rm -f *.o bin2h
