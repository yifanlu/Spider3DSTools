3DS 9.x Code Loading Utilities
===============================================================================

Here is a collection of scripts and tools used for loading code on 9.x 3DS. 
Check out [my posts](http://yifan.lu/category/devices/3ds/) to see how all 
this works. Please note this is only for developers and 3DS researchers and 
there is nothing here for the end user. This is NOT a CFW or any kind of ROM 
loader.

## How do I compile?

You need an arm-none-eabi-gcc toolchain installed. Then just run "make".
The toolchain that is tested with is <http://www.yagarto.de/>.

## Scripts

### LoadCode

This is an Spider ROP script that loads "code.bin" as ARM11 userland code from 
the SD card and runs it. It exploits the [gspwn](http://smealum.net/?p=517) 
vulnerability to load the code.

### LoadROP

This is an deobfuscated and cleaned up version of GW's first stage Launcher.dat 
loader with two changes. 1) No decryption is done, and 2) no indexing is done. 
This means you place the raw ROP.dat on the sdcard. It is tested to work with 
[regionthree](http://github.com/smealum/regionthree).

### MemoryDump

Taken from [WinterMute](https://github.com/WinterMute/ROPInstaller) ROP scripts 
for mset on 4.x and 6.x. Dumps memory to sdcard with 9.x spider.

### Code (UVLoader Lite)

A stripped down version of [UVLoader](http://github.com/yifanlu/UVLoader) that 
generates ARM code that runs with LoadCode. Currently it does nothing except 
display a random pattern on screen. Think of it as a lazy hello world. It is 
a starting point for your code.

### Browserify

Compile with "gcc -o browserify browserify.c" on your computer. Then convert 
any spider ROP payload to JS string with "browserify LoadCode.dat" (as an 
example).

## On spider ROP payloads

There are specific data at specific offsets that spider must see for the ROP to 
work. If you look in any of the example ROP scripts, you'll see where the data 
is placed. If you add/remove code, you must reposition all the InitData so it 
is at the sample place. Additionally, you must make sure the ROP script is 
exactly 0x300 bytes long. If anyone has a way to automate this, please send a 
pull request.
