# Glasgow RevC by 1bitSQUARED 

**WARNING: Proceed with caution. At every point I assume you know what you are doing and I can't be held responsible for any damage that you casue to your devices/equipment/lab etc.**

## SPI
In this section we will look into interacting with a SPI Flahs device using the Glasgow.

I will assume you know how to connect to a SPI TSOP8 flash chip. 

### 1. Setup and testing connection

I would suggest that before you plug-in the Glasgow, wire up the device to the SPI flash device. 
You can use a SOIC clip or test clips. These are then connected to the cables that will go to PORT A. 

How do I map the SPI flash chip to the port numbers. I would suggest that you stick with this ordering as I have come across issues in the past with interference. 

Pin Mapping: 
| SPI flash  | Glasgow |
| ------------- | ------------- |
|  SCK (Clock) | PA IO0 |
|  CS| PA IO1 |
|  COPI | PA IO2 |
|  CIPO | PA IO3 |
|  VCC | VIOA |
| GND | GND |

Double check you dont have any shorted connections anywhere. Now you can power up your Glasgow. 

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

### 2. Setup and testing connection

