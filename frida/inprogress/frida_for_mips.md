## MIPS binary cross-compile, Frida example


```
$ git clone --recursive https://github.com/frida/frida

```

Edit *releng/setup-env.sh* to find *host_toolprefix* with the cross-tool prefix :
```
$ vi releng/setup-env.sh
...
      mips)
        host_arch_flags="-march=mips1"
        host_toolprefix="mips-unknown-linux-$libc-"
...     

```

Edit *releng/config.site.in* to find *host_alias* with the cross-tool prefix :
```
$ vi releng/config.site.in 
...
  linux-mips)
    host_alias="$TARGET"
    cross_compiling=yes
    ;;
...
```

```
$ make -f Makefile.sdk.mk FRIDA_HOST=linux-mips

```
.. revisit it later 

```
