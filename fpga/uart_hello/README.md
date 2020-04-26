## Some Explanation Notes

*uart.v* is the UART library used by *uart_hello.v*

So you will want to have a play with the *uart_hello.v* 

If your board has a different CLK speed look at modifying the following values in *hello_uart.v*:

```verilog
  uart #(.baud_rate(9600), .sys_clk_freq(16000000))
```
TinyFPGA uses 16Mhz 
