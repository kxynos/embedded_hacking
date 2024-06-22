# Glasgow RevC by 1bitSQUARED 

**WARNING: Proceed with caution. At every point I assume you know what you are doing and I can't be held responsible for any damage that you casue to your devices/equipment/lab etc.**

## In-line SPI (minimum connections for read)
In this section we will look into interacting with a SPI Flahs device using the Glasgow for dumping/reading the chip that is still in place (in-line).

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

#### B) Applet: memory-25x

Chip identification using JEDEC:

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


