# Glasgow RevC by 1bitSQUARED 

## i2c - Reading

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
```
await iface.scan()
```
`{80}`
```
await iface.read(80, 2)
```
`<memory at 0xffff9a35b940>`
```
_.hex()
```
`'0042'`

For a quick dump of the address (given in binary): 
```
glasgow run i2c-initiator -V 3.3 --port A --pin-scl 0 --pin-sda 1 --pulls scan
```
