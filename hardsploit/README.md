## Hardsploit command line tool

Details of how to install ruby support for libusb : [installation-macOS-cmd.md](https://github.com/kxynos/embedded_hacking/blob/master/hardsploit/installation-macOS-cmd.md)

### Export SPI command line version (Qt library not needed)
File: [export_spi.rb](https://github.com/kxynos/embedded_hacking/blob/master/hardsploit/export_spi.rb)

[Hardsploit Github page](https://github.com/serma-safety-security)
#### Setup 

Install some libraries:

```bash
sudo apt-get install ruby ruby-dev cmake build-essential dfu-util libusb-1.0-0 bison openssl curl git-core zlib1g zlib1g-dev libssl-dev vim libsqlite3-0 libsqlite3-dev sqlite3 libxml2-dev git-core subversion autoconf xorg-dev libgl1-mesa-dev libglu1-mesa-dev
```

```ruby
gem install activerecord libusb sqlite3
```

Download the files (*50-hardsploit.rules* and *export_spi.rb*) from the hardsploit folder. 

Or copy this line:

```bash
SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="ffff", GROUP="plugdev", TAG+="uaccess"
```

* Copy the file *export_spi.rb* into the folder *hardsploit-api/Examples* in your *hardsploit-gui* setup or checkout just the api library *hardsploit-api*.

```bash
git clone --recursive https://github.com/OPALESECURITY/hardsploit-gui
```
or
```bash
git clone https://github.com/OPALESECURITY/hardsploit-api
```

* Copy *50-hardsploit.rules* into */etc/udev/rules.d/* (must be root/sudo) and reload the rules.
```bash
sudo udevadm control --reload-rules
```
* In order to change the chip settings edit the file *export_spi.rb* and setup the arguments to your chips specifications. When setting spi_speed make sure it matches one of the supported speeds in the @speeds lookup table.
```ruby
@chip_settings_ = {
      'spi_total_size' => 4194304,
    # 'spi_total_size' => 8388608,
      'start_address' => 0,
      'spi_mode' => 0,
      'spi_speed' => '15.00',
      'spi_command' => 3
    }
```

#### Executing Export SPI module (ruby)
Examples of how to execute the export SPI command : 
```bash
$ ruby export_spi.rb
$ ./export_spi.rb
$ ./export_spi.rb nofirmware
```
The *export_spi.rb* command has a **nofirmware** option, which makes dumping even faster (assuming SPI firmware is loaded into the FPGA already, the step is skipped). You might need to load the firmware once at the start and then it won't be needed. Use as and when required. The file that is generated is **always overwritten**. 

* Examples with output :
```bash
$ ruby export_spi.rb nofirmware
 ** Hardsploit SPI export ** 
[+] Number of hardsploit detected :1
Hardsploit is connected
API             : 2.0.0
Board           : HW:V1.00 SW:V1.0.3
FPGA            : V1.2.0
Microcontroller : V1.0.3
[+] HARDSPLOIT SPI export started 
[+] Progress : 100%  Start@ 2020-04-11 00:11:05 +0100  Stop@ 2020-04-11 00:11:11 +0100 
[+] HARDSPLOIT SPI export completed successfully
[+] Elasped time 6.5413 sec
[+] File saved in : /home/test/hardsploit-gui/hardsploit-api/Examples/hs_spi_export.bin
```
```bash
$ ruby export_spi.rb 
 ** Hardsploit SPI export ** 
[+] Number of hardsploit detected :1
Hardsploit is connected
API             : 2.0.0
Board           : HW:V1.00 SW:V1.0.3
FPGA            : V1.2.0
Microcontroller : V1.0.3
[+] Loading SPI firmware onto HARDSPLOIT
Date of last modification of the firmware 2019-04-08 15:45:07 +0100
[+] Progress : 100%  Start@ 2020-04-10 23:30:13 +0100  Stop@ 2020-04-10 23:30:14 +0100 
[+] HARDSPLOIT SPI export started 
[+] Progress : 100%  Start@ 2020-04-10 23:30:15 +0100  Stop@ 2020-04-10 23:30:22 +0100 
[+] HARDSPLOIT SPI export completed successfully
[+] Elasped time 6.688 sec
[+] File saved in : /home/test/hardsploit-gui/hardsploit-api/Examples/hs_spi_export.bin
```

N.B.: If you are having issues with the USB try [usb_add_remove.md](https://github.com/kxynos/embedded_hacking/blob/master/usb_add_remove.md)

TODO:
* Make chip settings a seperate file that can be loaded as an argument
