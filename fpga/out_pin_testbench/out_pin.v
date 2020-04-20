// FPGA
// Coded by Konstantinos Xynos (2020)
// MIT License 
//
// look in pins.pcf for all the pin names on the TinyFPGA BX board
module out_pin (
    input CLK,    // 16MHz clock
    output PIN_1,
    output LED,   // User/boot LED next to power LED
    output USBPU  // USB pull-up resistor

);
    // drive USB pull-up resistor to '0' to disable USB
    assign USBPU = 0;

    // keep track of time and location in blink_pattern
    reg [25:0] blink_counter;
    integer i;
    initial begin
	for (i=0;i<26;i=i+1) begin
		blink_counter[i]=0;
	end
    end
    ////////
    // make a simple blink circuit
    ////////

    // pattern that will be flashed over the LED over time
    wire [31:0] blink_pattern = 32'b1010_1000_1110_1110_1110_0010_101;

    // increment the blink_counter every clock
    always @(posedge CLK) begin
        blink_counter <= blink_counter + 1;
//	$display("counter: %b",blink_counter);
//	$display("counter25-0: %b",blink_counter[25:0]);
//	$display("counter25-21: %b",blink_counter[25:21]);
//	$display("counter4-0: %b",blink_counter[4:0]);
	//$display("counter_blink: %b",blink_pattern[blink_counter[25:21]]);
	//$display("counter_blink2: %b",blink_pattern[blink_counter[25:0]]);
    end
   

    // light up the LED according to the pattern
    assign LED = blink_pattern[blink_counter[25:21]];
//    assign LED = blink_pattern[blink_counter[4:0]];

    // send the blink_pattern to PIN_1
//    assign PIN_1 = blink_pattern[blink_counter[25:0]];
//    assign PIN_1 = blink_pattern[blink_counter[4:0]];
    assign PIN_1 = blink_pattern[blink_counter[25:21]];
endmodule
