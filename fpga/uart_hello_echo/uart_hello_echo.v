//
//  Code taken from https://github.com/pwmarcz/fpga-tools/tree/master/demo
//  Code hacking by Konstantinos Xynos (2020)
//  
//`include "uart.v"

// RX will output on PIN_1 and TX on PIN_2 on the TinyFPGA BX

module transmit_hello(input wire  CLK,
                      input wire  PIN_1, //RX
                      output wire PIN_2); //TX


`define GREETING_SIZE 12
`define RX_SIZE 3

  reg [7:0] rx_dat[0:7];

  wire [7:0] greeting[0:11];
  assign greeting[0]  = "H";
  assign greeting[1]  = "e";
  assign greeting[2]  = "l";
  assign greeting[3]  = "l";
  assign greeting[4]  = "o";
  assign greeting[5]  = " ";
  assign greeting[6]  = "W";
  assign greeting[7]  = "o";
  assign greeting[8]  = "r";
  assign greeting[9]  = "l";
  assign greeting[10] = "d";
  assign greeting[11] = "!";
  reg [3:0]  idx;
  reg [3:0]  idx2;

  reg        transmitted = 0;
  reg        command = 1;

  wire       reset = 0;
  reg        transmit;
  reg [7:0]  tx_byte;
  wire       received;
  wire [7:0] rx_byte;
  wire       is_receiving;
  wire       is_transmitting;
  wire       recv_error;

// TinyFPGA BX - 16 Mhz
  uart #(.baud_rate(57600), .sys_clk_freq(16000000))
  uart0(.clk(CLK),                    // The master clock for this module
        .rst(reset),                      // Synchronous reset
        .rx(PIN_1),                // Incoming serial line
        .tx(PIN_2),                // Outgoing serial line
        .transmit(transmit),              // Signal to transmit
        .tx_byte(tx_byte),                // Byte to transmit
        .received(received),              // Indicated that a byte has been received
        .rx_byte(rx_byte),                // Byte received
        .is_receiving(is_receiving),      // Low when receive line is idle
        .is_transmitting(is_transmitting),// Low when transmit line is idle
        .recv_error(recv_error)           // Indicates error in receiving packet.
        );

  always @(posedge CLK) begin
  
    if (received) begin
      rx_dat[idx2] <= rx_byte ;
      
      if (idx2 == `RX_SIZE - 1) begin
         idx2 <= 0;

      end else begin
        idx2 <= idx2 + 1;
      end
      if (!is_transmitting) begin
        transmit = 1;
        tx_byte = rx_byte;
        
      end

    end 
    
  end // always @ (posedge iCE_CLK)


endmodule // transmit_hello
