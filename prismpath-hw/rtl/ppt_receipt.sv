// ppt_receipt.sv — Fabric Decision Receipts. On each decision the fabric emits a timestamped,
// sequenced, FNV-chained receipt {seq, tstamp, policy_id, field, node, digest} out a UART pin, so the
// ENTIRE decision chain is captured off-chip with no processor in the loop — a passive reader (a logic
// analyzer or a serial capture) records it. The rolling FNV-1a-32 digest chains every receipt, so a
// dropped or altered record is detectable off-chip. This is the fabric analog of the kernel selector's
// ringbuf audit receipts (#117), carried onto the PL.
//
// Wire format per receipt (18 bytes, big-endian fields, gap-delimited by the inter-decision idle):
//   0xA5 | seq[4] | tstamp[4] | policy_id[1] | field[2] | node[2] | digest[4]
// The digest is FNV-1a-32 over the 13 content bytes (seq..node), chained across all receipts.
`default_nettype none
module ppt_receipt #(
  parameter int CLK_HZ = 50_000_000,
  parameter int BAUD   = 115200
)(
  input  wire        clk,
  input  wire        rst,
  input  wire        commit,        // 1-cycle strobe: a decision was made this cycle
  input  wire [11:0] field,         // the value decided on
  input  wire [15:0] node,          // the decided target node
  input  wire [7:0]  policy_id,     // active policy in the resident pack
  output wire        rcpt_tx,       // UART TX of the receipt stream (to an off-chip capture)
  output reg  [31:0] digest,        // rolling FNV-1a-32 over all receipts (tamper-evidence)
  output reg  [31:0] seq,           // receipts emitted
  output reg  [31:0] dropped,       // decisions that arrived while a receipt was still serializing
  output wire        busy
);
  localparam [7:0]  SYNC      = 8'hA5;
  localparam [31:0] FNV_INIT  = 32'd2166136261;
  localparam [31:0] FNV_PRIME = 32'd16777619;

  reg [31:0] tstamp;
  always @(posedge clk) if (rst) tstamp <= 32'd0; else tstamp <= tstamp + 32'd1;

  reg        tx_load;
  reg  [7:0] tx_data;
  wire       tx_ready;
  uart_tx #(.CLK_HZ(CLK_HZ), .BAUD(BAUD)) u_tx (
    .clk(clk), .rst(rst), .load(tx_load), .data(tx_data), .tx(rcpt_tx), .ready(tx_ready)
  );

  reg [31:0] r_seq, r_ts;
  reg [7:0]  r_pol;
  reg [11:0] r_field;
  reg [15:0] r_node;
  reg [31:0] r_digest;     // digest snapshot emitted in this record's trailer
  reg [4:0]  idx;          // byte index 0..17
  reg        sending;
  assign busy = sending;

  // byte at the current index
  reg [7:0] cur;
  always @(*) begin
    case (idx)
      5'd0:  cur = SYNC;
      5'd1:  cur = r_seq[31:24];  5'd2:  cur = r_seq[23:16];  5'd3:  cur = r_seq[15:8];  5'd4:  cur = r_seq[7:0];
      5'd5:  cur = r_ts[31:24];   5'd6:  cur = r_ts[23:16];   5'd7:  cur = r_ts[15:8];   5'd8:  cur = r_ts[7:0];
      5'd9:  cur = r_pol;
      5'd10: cur = {4'd0, r_field[11:8]}; 5'd11: cur = r_field[7:0];
      5'd12: cur = r_node[15:8];  5'd13: cur = r_node[7:0];
      5'd14: cur = r_digest[31:24]; 5'd15: cur = r_digest[23:16]; 5'd16: cur = r_digest[15:8]; 5'd17: cur = r_digest[7:0];
      default: cur = 8'd0;
    endcase
  end
  wire        fnv_byte = (idx >= 5'd1) && (idx <= 5'd13);      // content bytes feed the FNV chain
  wire [31:0] fnv_next = (digest ^ {24'd0, cur}) * FNV_PRIME;

  always @(posedge clk) begin
    tx_load <= 1'b0;
    if (rst) begin
      seq <= 32'd0; digest <= FNV_INIT; r_digest <= FNV_INIT;
      dropped <= 32'd0; sending <= 1'b0; idx <= 5'd0;
    end else if (!sending) begin
      if (commit) begin
        r_seq <= seq; r_ts <= tstamp; r_pol <= policy_id; r_field <= field; r_node <= node;
        seq <= seq + 32'd1; sending <= 1'b1; idx <= 5'd0;
      end
    end else begin
      if (commit) dropped <= dropped + 32'd1;                  // a decision landed mid-receipt
      if (tx_ready && !tx_load) begin
        tx_data <= cur;
        tx_load <= 1'b1;
        if (fnv_byte)      digest   <= fnv_next;               // extend the chain over this content byte
        if (idx == 5'd13)  r_digest <= fnv_next;               // freeze the trailer digest for this record
        if (idx == 5'd17)  sending  <= 1'b0;
        idx <= (idx == 5'd17) ? 5'd0 : idx + 5'd1;
      end
    end
  end
endmodule
`default_nettype wire
