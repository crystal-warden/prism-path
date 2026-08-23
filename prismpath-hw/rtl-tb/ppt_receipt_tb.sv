// ppt_receipt_tb.sv — cocotb harness: ppt_receipt's serial receipt stream looped back through the
// proven uart_rx, so the test reads clean {data, valid} bytes instead of sampling the wire by hand.
`default_nettype none
module ppt_receipt_tb #(
  parameter int CLK_HZ = 50_000_000,
  parameter int BAUD   = 2_500_000        // DIV=20: fast sim, comfortable uart_rx sampling margin
)(
  input  wire        clk,
  input  wire        rst,
  input  wire        commit,
  input  wire [11:0] field,
  input  wire [15:0] node,
  input  wire [7:0]  policy_id,
  output wire [7:0]  rx_data,
  output wire        rx_valid,
  output wire [31:0] seq,
  output wire [31:0] digest,
  output wire [31:0] dropped,
  output wire        busy
);
  wire rcpt_tx;
  ppt_receipt #(.CLK_HZ(CLK_HZ), .BAUD(BAUD)) dut (
    .clk(clk), .rst(rst), .commit(commit), .field(field), .node(node), .policy_id(policy_id),
    .rcpt_tx(rcpt_tx), .digest(digest), .seq(seq), .dropped(dropped), .busy(busy)
  );
  uart_rx #(.CLK_HZ(CLK_HZ), .BAUD(BAUD)) rx (
    .clk(clk), .rst(rst), .rx(rcpt_tx), .data(rx_data), .valid(rx_valid)
  );
endmodule
`default_nettype wire
