## MIPS binary cross-compile, Frida example
(might be out of date after commits fixes stuff)

I used Vagrant up for a quick cross-compile VM. 
Edit: Vagrantfile
```ruby
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

```bash
sudo apt install g++-mips-linux-gnu gcc-mips-linux-gnu flex bison python3-pip 
git clone --recursive https://github.com/frida/frida
```

Edit *releng/setup-env.sh* to find *host_toolprefix* with the cross-tool prefix :
```bash
$ vi releng/setup-env.sh
...
      mips)
        host_arch_flags="-march=mips1 -mfp32"

...   

```

If it complains about openssl issues try this:
Edit "openssl/Configure" 

(the file exists after it crashes on an error)

Edit "build/fs-tmp-linux-mips/openssl/Configure" at line 1233:     
```bash
openssl/Configure:        $value = '-mips2' if ($target =~ /mips32/);
```
```bash
openssl/Configure:        $value = '-mips1' if ($target =~ /mips32/);
```

```bash
$ make -f Makefile.sdk.mk FRIDA_HOST=linux-mips FRIDA_LIBC=gnu

Success! Here's your SDK: build/sdk-linux-mips.tar.bz2

```

Next attampt to make frida-gum (fails):
```bash
$ make -f Makefile.linux.mk gum-linux-mips FRIDA_LIBC=gnu
...
/home/vagrant/frida12/frida/build/tmp_thin-linux-mips/frida-gum/../../../frida-gum/ext/tinycc/tccasm.c:1217: undefined reference to `asm_gen_code'
/home/vagrant/frida12/frida/build/tmp_thin-linux-mips/frida-gum/../../../frida-gum/ext/tinycc/tccasm.c:1234: undefined reference to `asm_gen_code'
/home/vagrant/frida12/frida/build/tmp_thin-linux-mips/frida-gum/../../../frida-gum/ext/tinycc/tccasm.c:1234: undefined reference to `asm_gen_code'
collect2: error: ld returned 1 exit status
ninja: build stopped: subcommand failed.
Makefile.linux.mk:146: recipe for target 'build/frida_thin-linux-mips/lib/pkgconfig/frida-gum-1.0.pc' failed
make: *** [build/frida_thin-linux-mips/lib/pkgconfig/frida-gum-1.0.pc] Error 1
```

