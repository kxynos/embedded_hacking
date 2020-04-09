## MIPS binary cross-compile, Frida example


```
sudo apt install g++-mips-linux-gnu gcc-mips-linux-gnu flex bison 
git clone --recursive https://github.com/frida/frida

cd frida
wget https://github.com/mesonbuild/meson/releases/download/0.51.0/meson-0.51.0.tar.gz
tar zxf meson-0.51.0.tar.gz
mv meson-0.51.0 releng/meson

wget https://github.com/mesonbuild/meson/releases/download/0.51.0/meson-0.51.0.tar.gz; tar zxf meson-0.51.0.tar.gz; mv meson-0.51.0 releng/meson

export TARGET=mips-linux-gnu

```

Edit *releng/setup-env.sh* to find *host_toolprefix* with the cross-tool prefix :
```
$ vi releng/setup-env.sh
...
      mips)
        host_arch_flags="-march=mips1 -mfp32"
        host_toolprefix="$TARGET-"
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

Edit: *"xz/configure"*:
```
line: 6115
if test x$ac_cv_prog_cc_c99 = xno ; then
        as_fn_error $? "No C99 compiler was found." "$LINENO" 5
fi

if test x$ac_cv_prog_cc_c99 = xyes ; then
        as_fn_error $? "No C99 compiler was found." "$LINENO" 5
fi
```
Edit "Makefile.sdk.mk"                                                                                
```
line:289
-Dlibmount=false
-Dlibmount=disabled

line:301 and 295
-Dintrospection=false
-Dintrospection=disabled

line:11
openssl_version := 1.1.1b
```
Should get: 
```
...
openssl_version := 1.1.1f
...
...
$(eval $(call make-git-meson-module-rules,glib,build/fs-%/lib/pkgconfig/glib-2.0.pc,$(iconv) build/fs-%/lib/pkgconfig/zlib.pc build/fs-%/lib/pkgconfig/libffi.pc,$(glib_iconv_option) -Dselinux=disabled -Dxattr=false -Dlibmount=disabled -Dinternal_pcre=true -Dtests=false))
...
$(eval $(call make-git-meson-module-rules,json-glib,build/fs-%/lib/pkgconfig/json-glib-1.0.pc,build/fs-%/lib/pkgconfig/glib-2.0.pc,-Dintrospection=disabled -Dtests=false))
...
$(eval $(call make-git-meson-module-rules,libsoup,build/fs-%/lib/pkgconfig/libsoup-2.4.pc,build/fs-%/lib/pkgconfig/glib-2.0.pc build/fs-%/lib/pkgconfig/sqlite3.pc build/fs-%/lib/pkgconfig/libpsl.pc build/fs-%/lib/pkgconfig/libxml-2.0.pc,-Dgssapi=disabled -Dtls_check=false -Dgnome=false -Dintrospection=disabled -Dvapi=disabled -Dtests=false))
...
```

Edit "openssl/Configure"      
```
openssl/Configure:        $value = '-mips2' if ($target =~ /mips32/);
```
```
openssl/Configure:        $value = '-mips1' if ($target =~ /mips32/);
```


```
$ make -f Makefile.sdk.mk FRIDA_HOST=linux-mips

cd /capstone
./make.sh gcc
cd ..

```
.. revisit it later 

```
