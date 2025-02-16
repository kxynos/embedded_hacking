# Glasgow RevC by 1bitSQUARED 

## i2c - Reading parts

Easy interactive way to talk to an i2c chip is to use the Glasgow's REPL and i2c-initiator script. You will get a Python REPL that you can interact with.

Settings and wiring needed are as follows:

Port `A` and `SCL` is cable `0` and `SDA` is `1` we are setting `3.3v` and pull-up resistors:

```
glasgow repl i2c-initiator -V 3.3  --port A --pin-scl 0 --pin-sda 1 --pulls
```
```
I: g.device.hardware: generating bitstream ID xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
I: g.cli: running handler for applet 'i2c-initiator'
I: g.applet.interface.i2c_initiator: port(s) A voltage set to 3.3 V
I: g.applet.interface.i2c_initiator: port(s) A pull resistors configured
I: g.applet.interface.i2c_initiator: dropping to REPL; use 'help(iface)' to see available APIs
```

We can then scan for the address and use it to read 2 bytes from the chip:

```
>>> await iface.scan()
{80}

>>> await iface.read(80, 2)

<memory at 0xffff9a35b940>
_.hex()
'0042'
```

For a quick read of only the address (given in binary): 
```
glasgow run i2c-initiator -V 3.3 --port A --pin-scl 0 --pin-sda 1 --pulls scan
```
```
I: g.device.hardware: generating bitstream ID xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
I: g.cli: running handler for applet 'i2c-initiator'
I: g.applet.interface.i2c_initiator: port(s) A, B voltage set to 3.3 V
I: g.applet.interface.i2c_initiator: port(s) A, B pull resistors configured
I: g.applet.interface.i2c_initiator: scan found address 0b1010000
```

## i2c - Dumping (reading whole chip)
A modified version of read_edid.py that allows for dumping of a i2c using 128 byte blocks

[read_edid.py](https://github.com/kxynos/embedded_hacking/blob/master/glasgow/read_edid.py)

Example usage of reading 256 blocks at 128 bytes (only used as a calculation) and output to a file called output: 
```
glasgow script read_edid.py i2c-initiator --port A --pin-scl 0 --pin-sda 1 -V 3.3 --pulls output.bin -b 256
```
```
hexdump -C output.bin
```
