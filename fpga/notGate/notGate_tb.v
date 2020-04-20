module notGate_tb(); 
    wire out;
    reg clock;
     
    always begin
	#1 clock =!clock;
    end
     
    initial begin
	$dumpfile("notGate_tb.vcd");
	$dumpvars(0,notGate_tb);


	//Initialize clock
	clock = 0;
     
	//End simulation
	#10
	$finish;
    end
     
    notGate notGate_dut(clock, out);

endmodule
