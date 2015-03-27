CC=arm-none-eabi-gcc
CFLAGS=-fPIE -fno-zero-initialized-in-bss -std=c99 -mcpu=mpcore -fshort-wchar -O3
ASFLAGS=-nostartfiles -nostdlib
LD=arm-none-eabi-ld
LDFLAGS=-nostdlib
OBJCOPY=arm-none-eabi-objcopy
OBJCOPYFLAGS=

all: code.bin LoadROP.dat LoadCode.dat MemoryDump.dat

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

%.ro: %.S
	$(CC) -c -o $@ $< $(ASFLAGS)

%.elf: %.o
	$(LD) -o $@ $^ -T rop.x $(LDFLAGS)

code.elf: code.o
	$(LD) -o $@ $^ -T uvl.x $(LDFLAGS)

%.bin: %.elf
	$(OBJCOPY) -O binary $^ $@

%.dat: %.elf
	$(OBJCOPY) -S -O binary $^ $@

.PHONY: clean

clean:
	rm -rf *~ *.o *.elf *.bin *.s *.dat
