include $(ROOT_DIR)/Rules.mk

CC = gcc

INCLUDES += -I$(ROOT_DIR)/

CFLAGS += $(INCLUDES) -Wno-attributes -DUSING_DIET_LIBC=0

LIBS = $(BUILD_DIR)/libcommon_glibc/libcommon.a

SOURCES = main.c

OBJECTS = $(SOURCES:.S=.o)
OBJECTS := $(OBJECTS:.cpp=.o)

TARGET = ptrace.so

all: depend $(TARGET)
-include depend

%.o: %.S
	$(CC) -c $(CFLAGS) $< -o $@

%.o: %.cpp
	$(CC) -c $(CFLAGS) $< -o $@

$(TARGET): $(OBJECTS)
	./setup.py build_ext --inplace --include-dirs=$(ROOT_DIR) --libraries=common --library-dirs=$(BUILD_DIR)/libcommon_glibc/

asm: all
	objdump -S $(TARGET) > $(TARGET).s

clean:
	rm $(TARGET)

install:
	sudo ./setup.py install

depend:
	$(CC) $(CFLAGS) -MM $(SOURCES) > depend
