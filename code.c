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

int (*GX_SetTextureCopy)(void *input_buffer, void *output_buffer, unsigned int size, int in_x, int in_y, int out_x, int out_y, int flags) = 0x0011DD48;
int (*GSPGPU_FlushDataCache)(void *addr, unsigned int len) = 0x00191504;
int (*svcSleepThread)(unsigned long long nanoseconds) = 0x0023FFE8;

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

/********************************************//**
 *  \brief Entry point of UVLoader
 *
 *  \returns Zero on success, otherwise error
 ***********************************************/
int
uvl_entry ()
{
    int i;

    // makes random pattern on screen
    svcSleepThread (0x400000LL);
    svcSleepThread (0x400000LL);
    svcSleepThread (0x400000LL);
    for (i = 0; i < 3; i++) // do 3 times to be safe
    {
        GSPGPU_FlushDataCache (0x18000000, 0x00038400);
        GX_SetTextureCopy (0x18000000, 0x1F48F000, 0x00038400, 0, 0, 0, 0, 8);
        svcSleepThread (0x400000LL);
        GSPGPU_FlushDataCache (0x18000000, 0x00038400);
        GX_SetTextureCopy (0x18000000, 0x1F4C7800, 0x00038400, 0, 0, 0, 0, 8);
        svcSleepThread (0x400000LL);
    }

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
