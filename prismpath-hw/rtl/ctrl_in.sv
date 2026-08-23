// ctrl_in.sv — condition the raw board controls for the fabric: 2FF-synchronize the slide switches and
// push buttons, debounce each button, and emit a one-cycle strobe on a fresh press. Generic primitive:
// the demo's control-interpreter consumes `sw` (levels) and `btn_press` (edges) with no processor.
// THRESH is the number of clocks the button must hold to count (≈ CLK_HZ/1000 * debounce_ms).
`default_nettype none
module ctrl_in #(
  parameter int NBTN   = 4,
  parameter int NSW    = 2,
  parameter int THRESH = 250_000        // 5 ms @ 50 MHz
)(
  input  wire            clk,
  input  wire            rst,
  input  wire [NBTN-1:0] btn_raw,
  input  wire [NSW-1:0]  sw_raw,
  output reg  [NSW-1:0]  sw,            // synced switch levels
  output reg  [NBTN-1:0] btn_level,     // debounced button levels
  output reg  [NBTN-1:0] btn_press      // 1-cycle strobe on a 0->1 (press) transition
);
  localparam int CW = (THRESH <= 1) ? 1 : $clog2(THRESH + 1);

  // 2FF synchronizers
  reg [NBTN-1:0] b_m, b_s;
  reg [NSW-1:0]  s_m, s_s;
  always @(posedge clk) begin
    b_m <= btn_raw; b_s <= b_m;
    s_m <= sw_raw;  s_s <= s_m;
    sw  <= s_s;                          // switches: a sync is enough (slow, bounce-free enough)
  end

  // per-button debounce + rising-edge (press) detect
  genvar i;
  generate for (i = 0; i < NBTN; i = i + 1) begin : g_btn
    reg [CW-1:0] cnt;
    always @(posedge clk) begin
      btn_press[i] <= 1'b0;
      if (rst) begin
        cnt <= '0; btn_level[i] <= 1'b0;
      end else if (b_s[i] != btn_level[i]) begin
        if (cnt >= THRESH[CW-1:0]) begin
          btn_level[i] <= b_s[i];
          if (b_s[i]) btn_press[i] <= 1'b1;   // debounced press
          cnt <= '0;
        end else cnt <= cnt + 1'b1;
      end else cnt <= '0;
    end
  end endgenerate
endmodule
`default_nettype wire
