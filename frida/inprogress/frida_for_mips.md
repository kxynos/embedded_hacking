## MIPS binary cross-compile, Frida example
(might be out of date after commits fixes stuff)

I used Vagrant up for a quick cross-compile VM. 
Edit: Vagrantfile
```
# -*- mode: ruby -*-
# vi: set ft=ruby :
Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  config.disksize.size = '50GB'

  config.vm.provider "virtualbox" do |vb|
    vb.memory = "4096"
  end
end

```
Setup environment :

```
sudo apt install g++-mips-linux-gnu gcc-mips-linux-gnu flex bison python3-pip 
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
(if the file doesn't exist wait for it to crash)
Edit "openssl/Configure" 
or     
Edit "build/fs-tmp-linux-mips/openssl/Configure" at line 1233:     
```
openssl/Configure:        $value = '-mips2' if ($target =~ /mips32/);
```
```
openssl/Configure:        $value = '-mips1' if ($target =~ /mips32/);
```

```
$ make -f Makefile.sdk.mk FRIDA_HOST=linux-mips

Success! Here's your SDK: build/sdk-linux-mips.tar.bz2

```

Next attampt to make frida-gum:
```
$ make -f Makefile.linux.mk gum-linux-mips 
```

