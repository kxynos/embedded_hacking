# Glasgow RevC by 1bitSQUARED 

## SPI
In this section we will look into interacting with a SPI Flahs device using the Glasgow.

I will assume you know how to connect to a SPI TSOP8 flash chip. 

### 1. Setup and testing connection

I would suggest that before you plug-in the Glasgow, wire up the device to the SPI flash device. 
You can use a SOIC clip or test clips. 

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

