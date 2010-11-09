include $(ROOT_DIR)/Rules.mk

#INCLUDES = 

CFLAGS = -g -O0 -Wall -DDEBUG_LEVEL=0 $(INCLUDES)
LDFLAGS = 

LIBS = $(BUILD_DIR)/libcommon/libcommon.a

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
