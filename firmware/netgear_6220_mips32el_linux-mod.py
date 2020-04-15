#!/usr/bin/env python3
# 
# Copyright (C) 2020 Konstantinos Xynos
# 
# MIT License details found under LICENSE 
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
import stat

def my_syscall_write(ql, write_fd, write_buf, write_count, *rest):
    if write_fd is 2 and ql.file_des[2].__class__.__name__ == 'ql_pipe':
        ql.nprint("ql_custom: custom syscall_write return -1")
        ql_definesyscall_return(ql, -1)
    else:
        ql.nprint("ql_custom: custom syscall_write")
        syscall.ql_syscall_write(ql, write_fd, write_buf, write_count, *rest)

def my_syscall_stat64(ql, stat_path, buffr,  *rest):
    regreturn = 0
    ql.nprint("ql_custom: stat64 called")
    pathname = ql.mem.string(ql, stat_path)
    if pathname in ['setup.cgi','./']:
        pathname = 'www/' + pathname 

    ql.nprint("ql_custom: pathname: " + pathname)
    real_path = ql_transform_to_real_path(ql, pathname)

    ql.nprint("ql_custom: real_path: " + real_path)
    relative_path = ql_transform_to_relative_path(ql, pathname)[1:]

    ql.nprint("ql_custom: relative_path: " + relative_path)
    if os.path.exists(real_path) == False:
        regreturn = -1
        ql.nprint("ql_custom: stat64(%s) = %d : Not Found" % (real_path, regreturn))
    elif stat.S_ISREG(os.stat(real_path).st_mode):
        regreturn = 0
        ql.nprint("ql_custom: stat64(%s) = %d"% (relative_path, regreturn))
        ql.mem.string(stat_path, pathname)
        syscall.ql_syscall_stat64(ql, stat_path, buffr, *rest)
    else:
        regreturn = -1
        ql.nprint("ql_custom: stat64(%s) = %d : Not Found" % (relative_path, regreturn))
#    ql.mem.string(stat_path, pathname)
#    syscall.ql_syscall_stat64(ql, stat_path, buffr, *rest)
    ql.nprint("ql_custom: called stat64")
    ql_definesyscall_return(ql, regreturn)

def ql_write_string(ql, address, string_):
    string_bytes = bytes(string_, 'utf-8') + b'\x00'
    ql.mem.write(address, string_bytes)


def my_syscall_execve(ql, execve_pathname, execve_argv, execve_envp, *args, **kw ):
    # syscall.
    ql.nprint("ql_custom: ql_syscall_execve: called")
    
    pathname = ql.mem.string(execve_pathname)

    if pathname in ['setup.cgi','./']:
        pathname = 'www/' + pathname 

    ql.nprint("ql_custom: pathname: " + pathname)
    real_path = ql_transform_to_real_path(ql, pathname)

    ql.nprint("ql_custom: real_path: " + real_path)
    relative_path = ql_transform_to_relative_path(ql, pathname)

    ql.nprint("ql_custom: relative_path: " + relative_path)
    if os.path.exists(real_path) == False:
        regreturn = -1
        ql.nprint("execv(%s) = %d : Not Found" % (real_path, regreturn))
    elif stat.S_ISREG(os.stat(real_path).st_mode):
        regreturn = 0
        ql.nprint("execv(%s) = %d"% (relative_path, regreturn))
    else:
        regreturn = -1
        ql.nprint("execv(%s) = %d : Not Found" % (relative_path, regreturn))


    print(type(execve_pathname))
    print(execve_pathname)
    print(pathname)
    ql.mem.string(execve_pathname, pathname)
   # ql_write_string(ql,execve_pathname, pathname)
    #pathname_ = bytes(pathname, 'utf-8') + b'\x00'
    #ql.mem.write(execve_pathname, pathname_)
    print(type(execve_pathname))
    print(execve_pathname)
    pathname = ql.mem.string(ql, execve_pathname)
    print(pathname)
    syscall.ql_syscall_execve(ql, execve_pathname, execve_argv, execve_envp, *args, **kw)



def my_netgear(path, rootfs):
    ql = Qiling(
                path, 
                rootfs, 
                output      = "debug", 
                log_dir     = "qlog",
                log_console = True,
        #        log_console = False,
                mmap_start  = 0x7ffee000 - 0x800000,
                )

    ql.log_split        = True,
    ql.root             = False
    ql.bindtolocalhost  = True
    ql.multithread      = True
    ql.add_fs_mapper('/proc', '/proc')
#   ql.set_syscall(4004, my_syscall_write)
    ql.set_syscall(4213, my_syscall_stat64) # syscall stat64
    ql.set_syscall('execve', my_syscall_execve)
    ql.run()


if __name__ == "__main__":
    my_netgear(["squashfs-root/bin/mini_httpd",
                "-d","/www/",
                "-r","NETGEAR R6220",
                "-c","**.cgi",
                "-t","300"], 
                "squashfs-root")
