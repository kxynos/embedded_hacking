# NETGEAR firmware hackery 

## System Extraction

```bash
$  wget http://www.downloads.netgear.com/files/GDC/R6220/R6220-V1.1.0.86.zip
```

* Extract the system once:
```bash
$ binwalk -e R6220.img 
```

* Binwalk again to find squashfs system:

```bash
$ binwalk R6220.bin 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0xEBCCB4B4, created: 2015-09-25 14:29:54, image size: 133648 bytes, Data Address: 0xA0200000, Entry Point: 0xA0200000, data CRC: 0xE36D1B47, OS: Linux, CPU: MIPS, image type: Standalone Program, compression type: none, image name: "NAND Flash I"
108712        0x1A8A8         U-Boot version string, "U-Boot 1.1.3 (Sep 25 2015 - 10:29:47)"
262074        0x3FFBA         Sercomm firmware signature, version control: 256, download control: 0, hardware ID: "AYA", hardware version: 0x4100, firmware version: 0x86, starting code segment: 0x0, code size: 0x7300
2097152       0x200000        uImage header, header size: 64 bytes, header CRC: 0xE8CF0964, created: 2019-01-07 02:57:00, image size: 2566669 bytes, Data Address: 0x80001000, Entry Point: 0x8000F500, data CRC: 0x8E655EDA, OS: Linux, CPU: MIPS, image type: OS Kernel Image, compression type: lzma, image name: "Linux Kernel Image"
2097216       0x200040        LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, uncompressed size: 7605184 bytes
6291456       0x600000        Squashfs filesystem, little endian, version 4.0, compression:xz, size: 22643368 bytes, 1995 inodes, blocksize: 131072 bytes, created: 2019-01-07 02:56:51
35651584      0x2200000       Sercomm firmware signature, version control: 256, download control: 0, hardware ID: "AYA", hardware version: 0x4100, firmware version: 0x86, starting code segment: 0x0, code size: 0x7300
```

Extract manually the squashfs system. 
```bash
$ dd if=R6220.bin of=netgear-squashfs.bin skip=6291456 count=29360128 iflag=skip_bytes,count_bytes
57344+0 records in
57344+0 records out
29360128 bytes (29 MB, 28 MiB) copied, 3.69742 s, 7.9 MB/s
$ unsquashfs netgear-squashfs.bin
Parallel unsquashfs: Using 2 processors
1870 inodes (2376 blocks) to write
create_inode: could not create character device squashfs-root/usr/dev/urandom, because you're not superuser!

...
[================================================================================================================\      ] 2269/2376  95%

created 1485 files
created 125 directories
created 278 symlinks
created 0 devices
created 0 fifos
```

## System Emulation

```bash
