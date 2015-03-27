	.arm
	.section .rodata

#define DUMPSTART 	0x00100000
#define DUMPSIZE	0x00300000

	.global	_start
@---------------------------------------------------------------------------------
_start:
	@ mount SD
		.word 0x0010C2FC @ LDMFD   SP!, {R0,PC}
			.word 0x001050B3 @ R0 = "dmc:"
		.word 0x0019CA34 @ FS_MOUNTSDMC(), then LDMFD   SP!, {R3-R5,PC}
			.word 0xDEADBEEF @ R3, dummy
			.word 0xDEADBEEF @ R4, dummy
			.word 0xDEADBEEF @ R5, dummy
	@ open file
		.word 0x001946EB @ POP     {R0-R4,R7,PC}
			.word FILE @ R0 = this
			.word FileName @ R1 = filename
			.word 0x00000006 @ R2 = permission
			.word 0xDEADBEEF @ R3, dummy
			.word 0xDEADBEEF @ R4, dummy
			.word 0xDEADBEEF @ R7, dummy
		.word 0x0022FE0C @ IFile_Open(), then LDMFD   SP!, {R4-R7,PC}
			.word 0xDEADBEEF @ R4, dummy
			.word 0xDEADBEEF @ R5, dummy
			.word 0xDEADBEEF @ R6, dummy
			.word 0xDEADBEEF @ R7, dummy
		.word 0x001057C4 @ POP {PC}
	@ read memory
		.word 0x001946EB @ POP     {R0-R4,R7,PC}
			.word FILE @ R0 = this
			.word FILE + 32 @ R1 = written
			.word DUMPSTART @ R2 = buffer
			.word DUMPSIZE @ R3 = size
			.word 0xDEADBEEF @ R4, dummy
			.word 0xDEADBEEF @ R7, dummy
		.word 0x00168768 @ IFile_Write, then LDMFD   SP!, {R4-R11,PC}
			.word 0xDEADBEEF @ R4, dummy
			.word 0xDEADBEEF @ R5, dummy
			.word 0xDEADBEEF @ R6, dummy
			.word 0xDEADBEEF @ R7, dummy
			.word 0xDEADBEEF @ R8, dummy
			.word 0xDEADBEEF @ R9, dummy
			.word 0xDEADBEEF @ R10, dummy
			.word 0xDEADBEEF @ R11, dummy
	@ exit
		.word 0xDEADBEEF

	.section .rodata.init
InitData:
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.word 0, _start+0x8C, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, _start, 0x001057C4, 0x001057C4, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0x0010C2FC, _start+0x218, 0, 0, 0x001057C4, 0, 0, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
Self:
	.word Self, 0x001057C4, 0, 0, 0, 0, 0, 0, 0, 0x00130344, 0, 0, 0, 0, 0

	.section .rodata
	.align 2
FileName:
	.string16 "dmc:/memory.bin"

	.balign 32
FILE:	.fill	158, 1, 0
