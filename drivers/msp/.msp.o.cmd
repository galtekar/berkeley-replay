cmd_drivers/msp/msp.o := ld -m elf_i386   -r -o drivers/msp/msp.o drivers/msp/main.o drivers/msp/boot.o drivers/msp/paravirt.o drivers/msp/spt.o drivers/msp/ipt.o drivers/msp/fasync.o 
