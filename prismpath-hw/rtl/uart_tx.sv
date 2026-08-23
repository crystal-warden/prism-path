// uart_tx.sv — minimal 8N1 UART transmitter. Load a byte when `ready`; it shifts out LSB first at
// BAUD (start bit, 8 data, stop bit), idle high. Generic primitive; used by ppt_receipt to stream the
// fabric's decision receipts off-chip with no processor in the loop.
`default_nettype none
module uart_tx #(
  parameter int CLK_HZ = 50_000_000,
  parameter int BAUD   = 115200
)(
  input  wire       clk,
  input  wire       rst,
  input  wire       load,     // pulse: begin sending `data` (only when `ready`)
  input  wire [7:0] data,
  output reg        tx,        // serial out, idle high
  output wire       ready      // 1 = idle, can accept a byte
);
  localparam int DIV = CLK_HZ / BAUD;
  localparam [1:0] IDLE = 2'd0, START = 2'd1, DATA = 2'd2, STOP = 2'd3;
  reg [1:0]  st;
  reg [15:0] cnt;
  reg [2:0]  bi;
  reg [7:0]  sh;
  assign ready = (st == IDLE);

  always @(posedge clk) begin
    if (rst) begin
      st <= IDLE; tx <= 1'b1; cnt <= 16'd0; bi <= 3'd0;
    end else case (st)
      IDLE: begin
        tx <= 1'b1;
        if (load) begin sh <= data; tx <= 1'b0; cnt <= DIV[15:0]-16'd1; st <= START; end
      end
      START: if (cnt == 16'd0) begin
               tx <= sh[0]; sh <= {1'b0, sh[7:1]}; bi <= 3'd0; cnt <= DIV[15:0]-16'd1; st <= DATA;
             end else cnt <= cnt - 16'd1;
      DATA:  if (cnt == 16'd0) begin
               if (bi == 3'd7) begin tx <= 1'b1; cnt <= DIV[15:0]-16'd1; st <= STOP; end
               else begin tx <= sh[0]; sh <= {1'b0, sh[7:1]}; bi <= bi + 3'd1; cnt <= DIV[15:0]-16'd1; end
             end else cnt <= cnt - 16'd1;
      STOP:  if (cnt == 16'd0) st <= IDLE;
             else cnt <= cnt - 16'd1;
    endcase
  end
endmodule
`default_nettype wire
