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
//   0x28 W  AUTO_CTRL       [0] auto_mode, [1] stateful (resident FSM), [15:8] start_node,
//                           [23:16] pot_field_idx, [31:24] safe_node (reset-to fail-safe).
//                           The stateful/safe bits ride the signed pack's replayed arm write, so the
//                           mode is a signed property of the pack (FLAG_STATEFUL), never negotiated.
//   0x2C R  POT_NOW         [15:0] latched XADC pot from the datapath (PS calibration in auto mode)
//   0x30 R  CUR_NODE        [15:0] the resident node (datapath cur_node), [16] stateful — side-effect
//                           free, so the PS/OLED read the SAME resident band the fabric decides with

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
  input  wire        s_axi_rready,
  // --- datapath hooks: auto-mode routes the fabric FSM to the core; PS mode routes AXI ---
  input  wire        fsm_fld_we,
  input  wire [15:0] fsm_fld_idx,
  input  wire [1:0]  fsm_fld_type,
  input  wire [31:0] fsm_fld_val,
  input  wire        fsm_start,
  input  wire [15:0] fsm_node_idx,
  input  wire [15:0] pot_now,           // latched XADC pot, surfaced at POT_NOW (0x2C) for the PS
  input  wire [15:0] dbg_cur_node,      // datapath resident node, surfaced at CUR_NODE (0x30)
  output wire        auto_mode,          // AUTO_CTRL[0]
  output wire        auto_stateful,      // AUTO_CTRL[1] — resident-FSM mode (signed, rides the arm)
  output wire [15:0] auto_start_node,    // AUTO_CTRL[15:8]
  output wire [15:0] auto_pot_fidx,      // AUTO_CTRL[23:16]
  output wire [15:0] auto_safe_node,     // AUTO_CTRL[31:24] — reset-to fail-safe for the resident FSM
  output wire        core_busy,
  output wire        core_done,
  output wire        core_match,
  output wire [15:0] core_target,
  output wire        o_load_en,          // load bus mirror (the datapath taps sel==7 for the LUT)
  output wire [2:0]  o_load_sel,
  output wire [15:0] o_load_addr,
  output wire [31:0] o_load_data
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
  reg         auto_en;                 // AUTO_CTRL enable — PS mode (0, default/reset) vs auto (1)
  reg         auto_statef;             // AUTO_CTRL[1] — reset 0: stateless is the default, always
  reg  [15:0] auto_snode, auto_pfidx, auto_safe;
  wire        busy, done, match;
  wire [15:0] match_edge, target;

  // auto_en selects who drives the core's field-write + evaluate ports. The LOAD path is always
  // AXI (the PS loads the policy); reset to auto_en=0 makes this byte-identical to the PS-only design.
  ppt_interp #(
    .MAX_FIELDS(MAX_FIELDS), .MAX_ATOMS(MAX_ATOMS), .MAX_NODES(MAX_NODES),
    .MAX_EDGES(MAX_EDGES), .MAX_PROG(MAX_PROG)
  ) core (
    .clk(clk), .rst(core_rst),
    .load_en(load_en), .load_sel(load_sel), .load_addr(load_addr), .load_data(load_data),
    .fld_we   (auto_en ? fsm_fld_we   : fld_we),
    .fld_idx  (auto_en ? fsm_fld_idx  : fld_idx),
    .fld_type (auto_en ? fsm_fld_type : fld_type),
    .fld_val  (auto_en ? fsm_fld_val  : fld_val),
    .bump_en(bump_en), .bump_node(bump_node),
    .use_visits(auto_en ? 1'b0 : use_visits),
    .start    (auto_en ? fsm_start    : start),
    .node_idx (auto_en ? fsm_node_idx : node_idx),
    .busy(busy), .done(done), .match(match), .match_edge(match_edge), .target(target)
  );

  assign auto_mode       = auto_en;
  assign auto_stateful   = auto_statef;
  assign auto_start_node = auto_snode;
  assign auto_pot_fidx   = auto_pfidx;
  assign auto_safe_node  = auto_safe;
  assign core_busy = busy;  assign core_done = done;  assign core_match = match;
  assign core_target = target;
  assign o_load_en = load_en; assign o_load_sel = load_sel;
  assign o_load_addr = load_addr; assign o_load_data = load_data;

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
      auto_en <= 1'b0; auto_statef <= 1'b0;
      auto_snode <= 16'd0; auto_pfidx <= 16'd0; auto_safe <= 16'd0;
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
          6'h0A: begin auto_en     <= s_axi_wdata[0];             // AUTO_CTRL (0x28)
                       auto_statef <= s_axi_wdata[1];
                       auto_snode  <= {8'd0, s_axi_wdata[15:8]};
                       auto_pfidx  <= {8'd0, s_axi_wdata[23:16]};
                       auto_safe   <= {8'd0, s_axi_wdata[31:24]}; end
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
          6'h0B: s_axi_rdata <= {16'd0, pot_now};         // POT_NOW (0x2C) latched XADC pot
          6'h0C: s_axi_rdata <= {15'd0, auto_statef, dbg_cur_node};  // CUR_NODE (0x30), side-effect free
          default: s_axi_rdata <= 32'hDEADBEEF;
        endcase
      end
      if (s_axi_rvalid && s_axi_rready)
        s_axi_rvalid <= 1'b0;
    end
  end

endmodule

`default_nettype wire
