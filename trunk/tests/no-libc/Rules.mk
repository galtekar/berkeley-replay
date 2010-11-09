include $(ROOT_DIR)/Rules.mk

PERFCTR_DIR = $(ROOT_DIR)/perfctr
INCLUDES += -I$(PERFCTR_DIR)/linux/include/ -I$(ROOT_DIR)/VEX/pub -I$(PERFCTR_DIR)/usr.lib/ -I$(ROOT_DIR) -I$(ROOT_DIR)/dietlibc-0.30/include


CFLAGS = -g -O0 -Wall -nostdinc -DDEBUG_LEVEL=0 $(INCLUDES) -DUSING_DIET_LIBC
LDFLAGS = -static -nostdlib -L$(ROOT_DIR)/dietlibc-0.30/bin-i386

LIBS = $(BUILD_DIR)/libcommon/libcommon.a \
       $(ROOT_DIR)/dietlibc-0.30/bin-i386/dietlibc.a \
		 $(PERFCTR_DIR)/usr.lib/libperfctr.a \
		 $(LIBGCC)

OBJECTS = $(SOURCES:.S=.o)
OBJECTS := $(OBJECTS:.c=.o)

TARGET = test-bin

all: depend $(TARGET)
-include depend

%.o: %.S
	$(CC) -c $(CFLAGS) $< -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LDFLAGS) -Wl,--start-group $(LIBS) -Wl,--end-group -o $@

asm: all
	objdump -S $(TARGET) > $(TARGET).s

clean:
	rm -f $(OBJECTS) $(TARGET) depend $(TARGET).s

depend:
	gcc $(CFLAGS) -MM $(SOURCES) > depend
