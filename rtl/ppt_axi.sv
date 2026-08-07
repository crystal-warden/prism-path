// ppt_axi.sv — AXI4-Lite slave wrapper around ppt_interp: the PS-facing face of the
// interpreter. The PS (PYNQ/Python over MMIO) loads table images, writes field registers,
// pulses evaluate, and polls the result — the `make deploy` path is writes through this
// wrapper, never a bitstream change.
//
// Register map (byte offsets, 32-bit registers):
//   0x00 W  LOAD_SEL_ADDR   [18:16] load_sel, [15:0] load_addr   (latched)
//   0x04 W  LOAD_DATA       32b — writing pulses load_en with the latched sel/addr
//   0x08 W  FLD_IDX_TYPE    [17:16] field type, [15:0] field idx (latched)
//   0x0C W  FLD_VAL         32b — writing pulses fld_we
//   0x10 W  BUMP            [15:0] node — writing pulses bump_en (visits += 1, saturating)
//   0x14 W  CTRL            [15:0] node_idx, [16] use_visits — writing pulses start
//   0x18 R  STATUS          [0] busy, [1] done (latched), [2] match (of last evaluate)
//   0x1C R  RESULT          [15:0] target, [31:16] match_edge — reading clears done latch
//   0x20 W  SOFT_RST        any write resets the core (clears visits + field types)
//   0x24 R  MAGIC           reads 0x50505431 "PPT1" — presence/sanity check for the PS

`default_nettype none

module ppt_axi #(
  parameter int MAX_FIELDS = 16,
  parameter int MAX_ATOMS  = 64,
  parameter int MAX_NODES  = 16,
  parameter int MAX_EDGES  = 48,
  parameter int MAX_PROG   = 256
)(
  input  wire        s_axi_aclk,
  input  wire        s_axi_aresetn,
  // write address / data / response
  input  wire [7:0]  s_axi_awaddr,
  input  wire        s_axi_awvalid,
  output reg         s_axi_awready,
  input  wire [31:0] s_axi_wdata,
  input  wire [3:0]  s_axi_wstrb,
  input  wire        s_axi_wvalid,
  output reg         s_axi_wready,
  output reg [1:0]   s_axi_bresp,
  output reg         s_axi_bvalid,
  input  wire        s_axi_bready,
  // read address / data
  input  wire [7:0]  s_axi_araddr,
  input  wire        s_axi_arvalid,
  output reg         s_axi_arready,
  output reg [31:0]  s_axi_rdata,
  output reg [1:0]   s_axi_rresp,
  output reg         s_axi_rvalid,
  input  wire        s_axi_rready
);

  // ------------------------------------------------------------------ core
  wire clk = s_axi_aclk;
  reg  soft_rst;
  wire core_rst = ~s_axi_aresetn | soft_rst;

  reg         load_en;
  reg  [2:0]  load_sel;
  reg  [15:0] load_addr;
  reg  [31:0] load_data;
  reg         fld_we;
  reg  [15:0] fld_idx;
  reg  [1:0]  fld_type;
  reg  [31:0] fld_val;
  reg         bump_en;
  reg  [15:0] bump_node;
  reg         use_visits;
  reg         start;
  reg  [15:0] node_idx;
  wire        busy, done, match;
  wire [15:0] match_edge, target;

  ppt_interp #(
    .MAX_FIELDS(MAX_FIELDS), .MAX_ATOMS(MAX_ATOMS), .MAX_NODES(MAX_NODES),
    .MAX_EDGES(MAX_EDGES), .MAX_PROG(MAX_PROG)
  ) core (
    .clk(clk), .rst(core_rst),
    .load_en(load_en), .load_sel(load_sel), .load_addr(load_addr), .load_data(load_data),
    .fld_we(fld_we), .fld_idx(fld_idx), .fld_type(fld_type), .fld_val(fld_val),
    .bump_en(bump_en), .bump_node(bump_node), .use_visits(use_visits),
    .start(start), .node_idx(node_idx),
    .busy(busy), .done(done), .match(match), .match_edge(match_edge), .target(target)
  );

  // sticky result: done pulses one cycle; the PS polls
  reg done_l, match_l;
  reg [15:0] edge_l, target_l;
  always @(posedge clk) begin
    if (core_rst) begin
      done_l <= 1'b0; match_l <= 1'b0; edge_l <= '0; target_l <= '0;
    end else if (done) begin
      done_l <= 1'b1; match_l <= match; edge_l <= match_edge; target_l <= target;
    end else if (result_read || start) begin
      done_l <= 1'b0;
    end
  end

  // ------------------------------------------------------------------ AXI write channel
  wire wfire = s_axi_awvalid && s_axi_wvalid && !s_axi_bvalid;
  reg result_read;

  always @(posedge clk) begin
    // single-cycle pulses default low
    load_en <= 1'b0; fld_we <= 1'b0; bump_en <= 1'b0; start <= 1'b0; soft_rst <= 1'b0;
    s_axi_awready <= 1'b0; s_axi_wready <= 1'b0;

    if (!s_axi_aresetn) begin
      s_axi_bvalid <= 1'b0; s_axi_bresp <= 2'b00; use_visits <= 1'b0;
    end else begin
      if (wfire) begin
        s_axi_awready <= 1'b1; s_axi_wready <= 1'b1;
        s_axi_bvalid <= 1'b1; s_axi_bresp <= 2'b00;
        case (s_axi_awaddr[7:2])
          6'h00: begin load_sel <= s_axi_wdata[18:16]; load_addr <= s_axi_wdata[15:0]; end
          6'h01: begin load_data <= s_axi_wdata; load_en <= 1'b1; end
          6'h02: begin fld_type <= s_axi_wdata[17:16]; fld_idx <= s_axi_wdata[15:0]; end
          6'h03: begin fld_val <= s_axi_wdata; fld_we <= 1'b1; end
          6'h04: begin bump_node <= s_axi_wdata[15:0]; bump_en <= 1'b1; end
          6'h05: begin node_idx <= s_axi_wdata[15:0]; use_visits <= s_axi_wdata[16];
                       start <= 1'b1; end
          6'h08: soft_rst <= 1'b1;
          default: ;
        endcase
      end
      if (s_axi_bvalid && s_axi_bready)
        s_axi_bvalid <= 1'b0;
    end
  end

  // ------------------------------------------------------------------ AXI read channel
  always @(posedge clk) begin
    s_axi_arready <= 1'b0;
    result_read   <= 1'b0;
    if (!s_axi_aresetn) begin
      s_axi_rvalid <= 1'b0; s_axi_rresp <= 2'b00;
    end else begin
      if (s_axi_arvalid && !s_axi_rvalid) begin
        s_axi_arready <= 1'b1;
        s_axi_rvalid  <= 1'b1;
        s_axi_rresp   <= 2'b00;
        case (s_axi_araddr[7:2])
          6'h06: s_axi_rdata <= {29'd0, match_l, done_l, busy};
          6'h07: begin s_axi_rdata <= {edge_l, target_l}; result_read <= 1'b1; end
          6'h09: s_axi_rdata <= 32'h50505431;             // "PPT1"
          default: s_axi_rdata <= 32'hDEADBEEF;
        endcase
      end
      if (s_axi_rvalid && s_axi_rready)
        s_axi_rvalid <= 1'b0;
    end
  end

endmodule

`default_nettype wire
