// uart_rx.sv - minimal 8N1 UART receiver in the PL. Recovers one byte from a serial line, LSB first,
// sampling each bit at its centre. No processor in the path: this is how the ESP-NOW bridge's bytes
// enter the fabric so the Level M interpreter can decide on them directly. Default 115200 @ 50 MHz.
`default_nettype none
module uart_rx #(
  parameter int CLK_HZ = 50_000_000,
  parameter int BAUD   = 115200
)(
  input  wire       clk,
  input  wire       rst,        // synchronous, active high
  input  wire       rx,         // async serial in, idle high
  output reg  [7:0] data,       // last received byte
  output reg        valid       // 1-cycle strobe when `data` is fresh
);
  localparam int DIV  = CLK_HZ / BAUD;          // ticks per bit (50e6/115200 = 434)
  localparam int HALF = DIV / 2;

  // 2-flop synchroniser for the asynchronous input
  reg rx_m, rx_s;
  always @(posedge clk) begin rx_m <= rx; rx_s <= rx_m; end

  localparam [1:0] S_IDLE = 2'd0, S_START = 2'd1, S_DATA = 2'd2, S_STOP = 2'd3;
  reg [1:0]  st;
  reg [15:0] cnt;
  reg [2:0]  bit_i;
  reg [7:0]  sh;

  always @(posedge clk) begin
    valid <= 1'b0;
    if (rst) begin
      st <= S_IDLE; cnt <= 16'd0; bit_i <= 3'd0;
    end else case (st)
      S_IDLE:  if (!rx_s) begin st <= S_START; cnt <= HALF[15:0]; end   // falling edge = start bit
      S_START: if (cnt == 16'd0) begin
                 if (!rx_s) begin st <= S_DATA; cnt <= DIV[15:0]-16'd1; bit_i <= 3'd0; end
                 else        st <= S_IDLE;                              // false start, glitch
               end else cnt <= cnt - 16'd1;
      S_DATA:  if (cnt == 16'd0) begin
                 sh  <= {rx_s, sh[7:1]};                               // LSB first
                 cnt <= DIV[15:0]-16'd1;
                 if (bit_i == 3'd7) st <= S_STOP; else bit_i <= bit_i + 3'd1;
               end else cnt <= cnt - 16'd1;
      S_STOP:  if (cnt == 16'd0) begin
                 data  <= sh; valid <= 1'b1; st <= S_IDLE;             // stop bit centre; emit byte
               end else cnt <= cnt - 16'd1;
    endcase
  end
endmodule
`default_nettype wire
