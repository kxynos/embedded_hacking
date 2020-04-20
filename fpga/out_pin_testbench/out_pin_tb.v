`default_nettype none
//`timescale 100 ns / 10 ns
`timescale 1 ns / 1 ns

module out_pin_tb();
	reg CLK; 
	wire PIN_1; 
	wire PIN_2; 
	wire LED; 
	wire USBPU; 

	parameter DURATION =10000000;

	always begin
		#1;CLK=!CLK;
	end

	initial begin
		CLK=0;

		$dumpfile("out_pin_tb.vcd");
		$dumpvars(0,out_pin_tb);

		#(DURATION) $display("End of sim");
		$finish;
		
	end
	
//	$display("%b",blink_counter);
		
	out_pin dut(CLK, PIN_1, LED, USBPU);
//	out_pin_not dut2(CLK, PIN_1,PIN_2, LED, USBPU);

endmodule

`default_nettype wire
