// 
// Example from https://numato.com/kb/learning-fpga-verilog-beginners-guide-part-3-simulation-a7/
// 
module notGate(A, B);
    input wire A;
    output wire B;
    assign B = !A;
endmodule
