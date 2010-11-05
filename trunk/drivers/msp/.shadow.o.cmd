cmd_drivers/shpt/shadow.o := ld -m elf_i386   -r -o drivers/shpt/shadow.o drivers/shpt/main.o drivers/shpt/boot.o drivers/shpt/paravirt.o drivers/shpt/spt.o drivers/shpt/ipt.o drivers/shpt/fasync.o 
