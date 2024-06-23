## Hardsploit command line tool

Details of how to install ruby support for libusb : [installation-macOS-cmd.md](https://github.com/kxynos/embedded_hacking/blob/master/hardsploit/installation-macOS-cmd.md)

### Export SPI command line version (Qt library not needed)
File: [export_spi.rb](export_spi.rb)

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

#### Executing Export SPI module (ruby) with variable PIN mode

I programmed this PIN mode ([export_spi_pins.rb](export_spi_pins.rb)). This pin configuration enables you to reuse the cables from the *Tigard* set. This is an easy way to unplug the cable when needed and reuse the connections with a Salaea, Tigard etc. 

```bash
$ ruby export_spi_pins.rb --help
 ** Hardsploit SPI export ** 
usage: export_spi_pins.rb [options]
    -p, --pins [PINS]                Pick which pins to use. [0p3, 4p7, 3p0, default]
    -n, --nofirmware                 Don't automatically load the FPGA firmware (load at least once after powering on or changing functionality)
    -h, --help                       Show this message

```

* Examples with output :
```bash
$ ruby export_spi_pins.rb -p default
 ** Hardsploit SPI export ** 
false
Hardsploit is connected
[!] Loading SPI firmware loaded to FPGA
Date of last modification of the firmware 2023-11-01 12:51:29 +0100
[+] Progress : 100%  Start@ 2023-11-01 13:04:20 +0100  Stop@ 2023-11-01 13:04:21 +0100 
[+] Number of hardsploit detected :1
API             : 2.0.0
Board           : HW:V1.00 SW:V1.0.3
FPGA            : V1.2.0
Microcontroller : V1.0.3
[!] Warning : Some configurations won't work since line interference casues issues. Keep that in mind.
[!] Default pin layout CLK: A0, CS: A1, MOSI(SI): A2, MISO(SO): A3
[+] HARDSPLOIT SPI any rewiring complete 
[+] HARDSPLOIT SPI export started 
[+] Progress : 100%  Start@ 2023-11-01 13:04:22 +0100  Stop@ 2023-11-01 13:04:44 +0100 
[+] HARDSPLOIT SPI export completed successfully
[+] Elasped time 22.0719 sec
[+] File saved in : /home/[user_name]/embedded_hacking/hardsploit/hardsploit-api/Examples/hs_spi_export.bin
```

```bash
$ ruby export_spi_pins.rb -p 0p3
 ** Hardsploit SPI export ** 
false
Hardsploit is connected
[!] Loading SPI firmware loaded to FPGA
Date of last modification of the firmware 2023-11-01 12:51:29 +0100
[+] Progress : 100%  Start@ 2023-11-01 13:12:55 +0100  Stop@ 2023-11-01 13:12:55 +0100 
[+] Number of hardsploit detected :1
API             : 2.0.0
Board           : HW:V1.00 SW:V1.0.3
FPGA            : V1.2.0
Microcontroller : V1.0.3
[!] Warning : Some configurations won't work since line interference casues issues. Keep that in mind.
[!] Custom pins based on Saleae logic cable (0 to 3)
    Key: Function: Hardsploit pin - Saleae Pro Pin
	CLK: A0 - pin 0 | CS: A1 - pin 1
	SI: A2 - pin 2 | SO: A3 - pin 3
[+] HARDSPLOIT SPI any rewiring complete 
[+] HARDSPLOIT SPI export started 
[+] Progress : 100%  Start@ 2023-11-01 13:12:57 +0100  Stop@ 2023-11-01 13:13:19 +0100 
[+] HARDSPLOIT SPI export completed successfully
[+] Elasped time 22.0719 sec
[+] File saved in : /home/[user_name]/embedded_hacking/hardsploit/hardsploit-api/Examples/hs_spi_export.bin
```

#### Interact with SPI via custom commands

I have implemented the ability to send individual commands to the SPI flash device using the Hardploit. It is also possible to avoid uploading the firmware for even faster interactions. I have added a `-o` flag also to surpress all unwanted output (only the result is outputed as a list).

```bash
$ ruby interact_spi.rb -n -c 9f,0,0,0,0 -o -h
Usage: interact_spi [options]
    -n, --nofirmware                 Avoid uploading firmware
    -c hex_value1,hex_value2,...,    An input array used for command input, use hex values e.g., 9f,0,0,0,0
        --command
    -o, --nooutput                   Avoid output status messages, only the output result is printed
```

Only the result is outputed as a list of hex values

```bash
$ ruby interact_spi.rb -n -c 9f,0,0,0,0 -o 
[ff,ff,9d,46,7f]
```

No firmware is uploaded

```bash

$ ruby interact_spi.rb -n -c 9f,0,0,0,0 
 ** Hardsploit SPI command ** 
[+] Avoid uploading firmware flag set: true
[+] Number of hardsploit detected :1
Hardsploit is connected
API             : 2.0.0
Board           : HW:V1.00 SW:V1.0.3
FPGA            : V1.2.0
Microcontroller : V1.0.3
[+] HARDSPLOIT SPI command started 
[+] Sending command: ["9f", "0", "0", "0", "0"]
[+] Sending command(int): [159,0,0,0,0]
[+] Reply: [ff,ff,9d,46,7f]

[+] HARDSPLOIT SPI command completed successfully
```

Custom command with firmware upload and very verbose

```bash

$ ruby interact_spi.rb -c 9f,0,0,0,0 
 ** Hardsploit SPI command ** 
[+] Number of hardsploit detected :1
Hardsploit is connected
API             : 2.0.0
Board           : HW:V1.00 SW:V1.0.3
FPGA            : V1.2.0
Microcontroller : V1.0.3
[+] Loading SPI firmware onto HARDSPLOIT
Date of last modification of the firmware 2023-11-01 12:51:29 +0100
[+] Progress : 100%  Start@ 2024-06-23 20:13:31 +0200  Stop@ 2024-06-23 20:13:32 +0200 
[+] HARDSPLOIT SPI command started 
[+] Sending command: ["9f", "0", "0", "0", "0"]
[+] Sending command(int): [159,0,0,0,0]
[+] Reply: [ff,ff,9d,46,7f]

[+] HARDSPLOIT SPI command completed successfully
[+] Elasped time 0.6861 sec
```


#### Extras

N.B.: If you are having issues with the USB try [usb_add_remove.md](https://github.com/kxynos/embedded_hacking/blob/master/usb_add_remove.md)

TODO:
* Make chip settings a seperate file that can be loaded as an argument
