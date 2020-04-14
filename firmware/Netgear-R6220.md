# NETGEAR firmware hackery 

## System Extraction (manual)
Linux system used Kali 2018.4:
```bash
# uname -a
Linux kali 4.18.0-kali2-amd64 #1 SMP Debian 4.18.10-2kali1 (2018-10-09) x86_64 GNU/Linux
```
Download the firmware to try out, Netgear R6220 Version V1.1.0.86:
```bash
$  wget http://www.downloads.netgear.com/files/GDC/R6220/R6220-V1.1.0.86.zip
```

* Extract the system once:
```bash
$ binwalk -e R6220-V1.1.0.86.img  
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
...(cut down)
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

...(cut down)
[================================================================================================================\      ] 2269/2376  95%

created 1485 files
created 125 directories
created 278 symlinks
created 0 devices
created 0 fifos
```

## System Emulation using Qiling Framework

Will give Qiling Framework ([on github](https://github.com/qilingframework/qiling)) a try since it looks very promising from an instrumentation point of view. 

After extracting the firmware, change into the root account and enter the squashfs-root folder.
```bash
$ sudo su
$ cd squashfs-root
```
Manually correct links and folders (firmadyn): 
```bash
$ rm var
$ mkdir var
$ mkdir var/run
$ rm etc
$ rm etc_ro
$ ln -s usr/etc ./etc
$ ln -s usr/etc_ro/ ./etc_ro
$ rm www
$ mv www.eng www
$ rm mnt
$ rm root
$ mkdir mnt
$ mkdir root
```

Setup the python script to start things. This is a slightly modified example provided by Qlinig Framework.
Save the following as *netgear_6220_mips32el_linux_modified.py*:
```python3
#!/usr/bin/env python3
# 
# Qiling Framework, 2020 (https://github.com/qilingframework/qiling)
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# After mapping /proc there will be a /dev/mtdblock11 missing and crash
# To fix this,
#   - cd $yourfirmware_rootfs/dev
#   - dd if=/dev/zero of=mtdblock11 bs=1024 count=129030
#   - mkfs.ext4 mtdblock11
# 
# This firmware will more or less alive now.

import sys
sys.path.append("..")
from qiling import *
from qiling.os.posix import syscall


def my_syscall_write(ql, write_fd, write_buf, write_count, *rest):
    if write_fd is 2 and ql.file_des[2].__class__.__name__ == 'ql_pipe':
        ql_definesyscall_return(ql, -1)
    else:
        syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *rest)


def my_netgear(path, rootfs):
    ql = Qiling(
                path, 
                rootfs, 
                output      = "debug", 
                log_dir     = "qlog",
                log_console = True,
#                log_console = False,
                mmap_start  = 0x7ffee000 - 0x800000,
                )

    ql.log_split        = True,
    ql.root             = False
    ql.bindtolocalhost  = True
    ql.multithread      = True
    ql.add_fs_mapper('/proc', '/proc')
#    ql.set_syscall(4004, my_syscall_write) # disabled for this example
    ql.run()


if __name__ == "__main__":
    my_netgear(["squashfs-root/bin/mini_httpd",
                "-d","/www",
                "-r","NETGEAR R6220",
                "-c","**.cgi",
                "-t","300"], 
                "squashfs-root")
```

Execute the script. You will get lots of output to the screen since *log_console* is set to *True*. 
```bash
# python netgear_6220_mips32el_linux_modified.py 
# netstat -na | more
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN
```
Test if it "sort of" works:

Save this into a file *http.txt* (notice the new line at the end, you need it):
```html
GET / HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:74.0) Gecko/20100101 Firefox/74.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Cache-Control: max-age=0


```
Give it a run:
```bash
# cat http.txt | nc -v 127.0.0.1 8080
localhost [127.0.0.1] 8080 (http-alt) open
HTTP/1.1 503 No Shares Available
Server: 
Date: Tue, 14 Apr 2020 12:00:57 GMT
Content-Type: text/html
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1;mode=block
X-Content-Type-Options: nosniff
Connection: close

		<HTML>
		<HEAD><TITLE>503 No Shares Available</TITLE></HEAD>
		<BODY BGCOLOR="#cc9999" TEXT="#000000" LINK="#2020ff" VLINK="#4040cc">
		<H4>503 No Shares Available</H4>

</BODY>
</HTML>
```
It is running now what:
* Where to next ? Figure out why it is not correctly loading the files from **www**. 
* Check the calls made earlier and try to intercept them using Qiling Framework. 
* If you can intercept calls, modify them. 

## Issue(s) (with solution(s))

### Issue 1:

I was getting this error. It would seem it is a permissions issue and running as root (not ideal) should solve it. 
```bash
(stack trace)
unicorn.unicorn.UcError: Invalid memory read (UC_ERR_READ_UNMAPPED)
```
Solution:
* Change to root account and try executing from there.
* Also have a look at trace and see if there were any issues. I noticed that there were configuration files not being read or accessible. Sometimes even creating a folder and empty file might be enough for it to move on (e.g. File Not Found errors).

### Issue 2: 

If keystone fails with this error :
```bash
  File "/usr/local/lib/python3.7/dist-packages/keystone/keystone.py", line 75, in <module>
    raise ImportError("ERROR: fail to load the dynamic library.")
ImportError: ERROR: fail to load the dynamic library.
```

Example solution:
```bash
sudo cp -R /usr/local/lib/python3.7/dist-packages/usr/lib/python3/dist-packages/keystone/libkeystone.so /usr/local/lib/python3.7/dist-packages/keystone/
```
