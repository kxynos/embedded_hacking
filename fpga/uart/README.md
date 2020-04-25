## Some Explanation Notes

*uart.v* is the UART library used by *uart_hello.v*

So you will want to have a play with the *uart_hello.v* 

If your board has a different CLK speed look at modifying the following values in *hello_uart.v*

```verilog
  uart #(.baud_rate(9600), .sys_clk_freq(12000000))
```

When I kept 9600 as a baud rate, like in the example above, and I check the output via a Logic Analyzer, I noticed that the signal being produced had an incorrect baud rate. It was not compatible or inline with what I had provided. I am not a Verilog expert and can't go into the details. If you do use these libraries at least you can produce one consistent baud rate. 

I read up the article on [https://www.fpga4fun.com/SerialInterface2.html](https://www.fpga4fun.com/SerialInterface2.html) and understood that I needed to do some calculations. So I ended up with the following\*:

```python
If we have/want 57600 baud rate (bits/s)*:
1*(pow(10,6))/57600. = 17.36111111111111 us
17.36 us * 16 bits = 277.76 
(12*pow(10,6))/277.76 = 43202
``` 

Using **43202** as the baud rate in *uart_hello.v* then provided the correct results. I further verified this with the logical analyzer. The timings and decoding by Saleae Pro where in-line with what is expected.

\*where us is micro-second