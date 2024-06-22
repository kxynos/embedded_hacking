# Glasgow RevC by 1bitSQUARED 

**WARNING: Proceed with caution. At every point I assume you know what you are doing and I can't be held responsible for any damage that you casue to your devices/equipment/lab etc.**

## In-line SPI (minimum connections for read)
In this section we will look into interacting with a SPI Flahs device using the Glasgow RevC [https://glasgow-embedded.org](https://glasgow-embedded.org) or [glasgow embedded github repo](https://github.com/GlasgowEmbedded/glasgow/) for dumping/reading the chip that is still in place (in-line).

In this page, we don't need to remove any flash chips. 

I will assume you know how to connect to a SPI TSOP8 flash chip. 

Assumptions, you have read the datasheet and you are interacting with a SPI Flash storage device. 
We are also using the least amount of connection to just interact and read from the SPI Flash. 

### 1. Setup and testing connection

I would suggest that before you plug-in/power-up the Glasgow, wire up the device to the SPI flash device. 
You can use a SOIC clip or test clips. These are then connected to the cables that will go to PORT A. 

How do I map the SPI flash chip to the port numbers? 

I would suggest that you stick with this ordering as I have come across issues in the past with interference. 

Pin Mapping: 
| SPI flash  | Glasgow |
| ------------- | ------------- |
| SCK (Clock) | PA IO0 |
| CS | PA IO1 |
| COPI | PA IO2 |
| CIPO | PA IO3 |
| VCC | VIOA |
| GND | GND |

Double check you dont have any shorted connections anywhere. 

Now you can power up your Glasgow. 

P.S.: Usually the target device won't need to be powered up since we are providing just enough power for the SPI Flash chip to operate.

Depending on your requirements, you might not want to power the device using the Glasgow. (I have not tested this yet.) 

Check that Glasgow is connected:

```
glasgow list
```

Result:

```
C3-xxxxxxxxxxxxxxxx
```

Check the voltage ranges:

```
glasgow voltage
```

Result:

```
Port	Vio	Vlimit	Vsense	Vsense(range)
A      0.0	5.5	   0.0	    0.0-5.5	
B      0.0	5.5	   0.0	    0.0-5.5
```

Set the voltage maximum limit on Port A (only A):

```
glasgow voltage-limit A 3.3
```

Result:

```
Port	Vio	Vlimit	Vsense	Vsense(range)
A      0.0	3.3	   0.0	    0.0-5.5	
B      0.0	5.5	   0.0	    0.0-5.5
```

### 2. Interacting with the SPI flash device (target/peripheral) 

The Glasgow software comes with applets (`glasgow run --help`). 

There are currently two that can be used to communicate with the SPI flash chip. 

#### A) Applet: spi-controller

This is more of a manual process and you need to read the chip's datasheet. Check the markings on the SPI flash chip. 

The example one I am using here is a IS25CQ032 and a datasheet can be found here: [https://www.mouser.com/datasheet/2/198/25CQ032-258519.pdf](https://www.mouser.com/datasheet/2/198/25CQ032-258519.pdf) 

A nice and easy and quick test that we can complete is the JEDEC ID Read (0x9F) (page 15 in datasheet). 
This will output the Manufacturer ID1, Manufacturer ID2, and Device ID2. 
The important point here to remeber is that SPI will only return the amount of bytes we send. 
So we will send the instruction 0x9F which is one byte, and then send 3 bytes of zeros (dummy data which is ignored) to get back the Manufacturer ID1, Manufacturer ID2, and Device ID2.
So the command we will send to the SPI flash device(target/peripheral) will be '9f000000'. 

Notice, my circuit makes use of 3.3V and therefore I have set it to 3.3v. 

Chip identification using JEDEC hex command:

```
glasgow run spi-controller -V 3.3 --pin-sck 0 --pin-cs 1 --pin-copi 2 --pin-cipo 3 '9f000000'
```

Result (identifying a IS25CQ032):

```
I: g.device.hardware: device already has bitstream ID XXXXXXXXXX
I: g.cli: running handler for applet 'spi-controller'
I: g.applet.interface.spi_controller: port(s) A, B voltage set to 3.3 V
007f9d46
```

And the end result is '007f9d46'. Manufacture ID2=0x7f, Manufacture ID1 = 0x9d, Device ID2=0x46

If you want Device ID1 (RDID (0xAB)) try 'ab00000000' and you should get '0000000015' or Device ID2=0x15. 

From datasheet:

| Product Identification | Hex Code |
| ------------- | ------------- |
| Manufacture ID1 | 9Dh |
| Manufacture ID2 | 7Fh |
| Device ID1 | 15h |
| Device ID2 | 46h |


#### B) Applet: memory-25x - identify

You can also avoid doing everything manually and just use the `memory-25x` applet. 

Chip identification using JEDEC via memory-25x identify command:

```
glasgow run memory-25x -V 3.3 --pin-sck 0 --pin-cs 1 --pin-copi 2 --pin-cipo 3 identify
```

Result (identifying a IS25CQ032):

```
I: g.device.hardware: generating bitstream ID XXXXXXXXXX
I: g.cli: running handler for applet 'memory-25x'
I: g.applet.memory.25x: port(s) A, B voltage set to 3.3 V
I: g.applet.memory.25x: JEDEC manufacturer 0x9d (Lucent (AT&T)) device 0x15 (8-bit ID)
I: g.applet.memory.25x: JEDEC manufacturer 0x7f (unknown) device 0xXXXXX (16-bit ID)
I: g.applet.memory.25x: device does not have valid SFDP data: SFDP signature not present
```


#### C) Applet: memory-25x - read

Geting help about the 'memory-25x' read function:

```
glasgow run memory-25x read -h
```

Result:

```

usage: glasgow run memory-25x read [-h] [-f FILENAME] ADDRESS LENGTH

positional arguments:
  ADDRESS               read memory starting at address ADDRESS, with wraparound
  LENGTH                read LENGTH bytes from memory

options:
  -h, --help            show this help message and exit
  -f FILENAME, --file FILENAME
                        write memory contents to FILENAME
```            

Therefore, we need to set the start and end size of the capture (notice you can capture specific areas if you like. Also specify a filename. 

If you are reading a 32M-Bit flash chip use '4194304' bytes and for a 64M-Bit one use '8388608' bytes. 

Reading the chip (not fast mode) via memory-25x read command:

```
glasgow run memory-25x -V 3.3 --pin-sck 0 --pin-cs 1 --pin-copi 2 --pin-cipo 3 read 0 4194304 -f firmware.bin
```

Result (identifying a IS25CQ032):

```
I: g.device.hardware: device already has bitstream ID XXXXXXXXXXX
I: g.cli: running handler for applet 'memory-25x'
I: g.applet.memory.25x: port(s) A, B voltage set to 3.3 V
1114112/4194304 bytes done; reading address 0x110000
```

Check the contents of firmware.bin file:

Command: 

```
hexdump -C firmware.bin
```

Result:
```
00000000  48 44 52 30 04 fa 00 00  00 00 00 00 60 00 02 00  |HDR0........`...|
[...]
```

### Statistics - SPI flash read speed

#### Using the Glasgow 0.1.dev2053+g3940a01

| Chip | Size | Total Time |
| ------------- | ------------- | ------------- |
| IS25CQ032 | 4194304 | real 5m36.483s  |
