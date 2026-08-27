// ppt_datapath_finale.sv — the pure-fabric finale: the zeck decision datapath PLUS the fabric control
// plane. Buttons and switches run through a signed control table (ppt_ctrl_interp) that can hot-swap
// the decision policy with NO processor: the pack loader replays the compiler's signed AXI writes into
// ppt_axi's existing slave through a 2:1 write mux (PS boot setup on one side, fabric swaps on the
// other). The finale front-end (ppt_field_ctrl) shapes the field in and the LED out, gated by the
// signed profile, so BTN3's meta-swap changes what every other control means. The certified
// ppt_interp/ppt_axi are untouched; build with PPT_PACK_REAL + PPT_CTRL_PACK_REAL for the signed packs.
//
// Cert hooks (scriptable silicon cert, no hands): `inj` ORs into the raw buttons/switches
// ([3:0]=BTN, [5:4]=SW, via an axi_gpio the PS drives), and `status` reads back
// {thresh_sel[1:0], color_idx[2:0], mute, loading, profile}.

`default_nettype none

module ppt_datapath_finale #(
  parameter int MAX_FIELDS = 16,
  parameter int MAX_ATOMS  = 64,
  parameter int MAX_NODES  = 16,
  parameter int MAX_EDGES  = 48,
  parameter int MAX_PROG   = 256
)(
  input  wire        clk,
  input  wire        resetn,
  // AXI4-Lite slave (PS face)
  input  wire [7:0]  s_axi_awaddr,
  input  wire        s_axi_awvalid,
  output wire        s_axi_awready,
  input  wire [31:0] s_axi_wdata,
  input  wire [3:0]  s_axi_wstrb,
  input  wire        s_axi_wvalid,
  output wire        s_axi_wready,
  output wire [1:0]  s_axi_bresp,
  output wire        s_axi_bvalid,
  input  wire        s_axi_bready,
  input  wire [7:0]  s_axi_araddr,
  input  wire        s_axi_arvalid,
  output wire        s_axi_arready,
  output wire [31:0] s_axi_rdata,
  output wire [1:0]  s_axi_rresp,
  output wire        s_axi_rvalid,
  input  wire        s_axi_rready,
  // XADC DRP master (read-only)
  output reg         drp_den,
  output reg  [6:0]  drp_daddr,
  output wire [15:0] drp_di,
  output wire        drp_dwe,
  input  wire [15:0] drp_do,
  input  wire        drp_drdy,
  // LEDs
  input  wire [5:0]  ps_led,
  output wire [5:0]  led_o,
  // PL-native UART RX (walker's zeck frames)
  input  wire        uart_rx_pin,
  // board controls (direct PL pins)
  input  wire [3:0]  btn_i,
  input  wire [1:0]  sw_i,
  // cert hooks
  input  wire [7:0]  inj,          // [3:0] OR into buttons, [5:4] OR into switches
  output wire [7:0]  status        // {thresh_sel[1:0], color_idx[2:0], mute, loading, profile}
);

  localparam [6:0] DADDR_VAUX1 = 7'h11;
  localparam [1:0] TY_INT      = 2'd2;
  localparam int   NB          = (MAX_NODES <= 1) ? 1 : $clog2(MAX_NODES);

  // --- hooks to/from ppt_axi ---
  wire        auto_mode, auto_stateful;
  wire [15:0] auto_start_node, auto_pot_fidx, auto_safe_node;
  wire        core_done, core_match, core_busy;
  wire [15:0] core_target;
  wire        o_load_en;
  wire [2:0]  o_load_sel;
  wire [15:0] o_load_addr;
  wire [31:0] o_load_data;

  reg  [11:0] pot;

  // --- native Facet decode (unchanged from the zeck datapath) ---
  wire [7:0]  uart_byte;
  wire        uart_valid;
  wire [2:0]  zk_band;
  wire        zk_band_valid;
  reg  [11:0] band_field;
  uart_rx #(.CLK_HZ(50_000_000), .BAUD(115200)) u_rx (
    .clk(clk), .rst(~resetn), .rx(uart_rx_pin), .data(uart_byte), .valid(uart_valid)
  );
  zeck_frame_rx #(.GAP_TICKS(50_000)) u_frame (
    .clk(clk), .rst(~resetn), .byte_valid(uart_valid), .byte_in(uart_byte),
    .band(zk_band), .band_valid(zk_band_valid)
  );
  always @(posedge clk) begin
    if (!resetn) band_field <= 12'd0;
    else if (zk_band_valid) begin
      case (zk_band)
        3'd0:    band_field <= 12'd200;
        3'd1:    band_field <= 12'd500;
        3'd2:    band_field <= 12'd1000;
        3'd3:    band_field <= 12'd1800;
        default: band_field <= 12'd2600;
      endcase
    end
  end

  // --- the fabric control plane: conditioned controls -> signed table -> pack loader ---
  wire [1:0] cw_sw;
  wire [3:0] cw_press;
  ctrl_in #(.NBTN(4), .NSW(2)) u_cin (
    .clk(clk), .rst(~resetn),
    .btn_raw(btn_i | inj[3:0]), .sw_raw(sw_i | inj[5:4]),
    .sw(cw_sw), .btn_level(), .btn_press(cw_press)
  );

  wire       cp_profile, cp_mute, cp_decin, cp_loading;
  wire [1:0] cp_src, cp_thresh;
  wire [2:0] cp_color;
  wire [7:0]  l_awaddr;
  wire        l_awvalid, l_awready, l_wvalid, l_wready, l_bvalid, l_bready;
  wire [31:0] l_wdata;
  wire [3:0]  l_wstrb;
  wire [1:0]  l_bresp;
  ppt_ctrl_plane #(.NBTN(4), .NSW(2)) u_cp (
    .clk(clk), .rst(~resetn),
    .sw(cw_sw), .btn_press(cw_press),
    .m_awaddr(l_awaddr), .m_awvalid(l_awvalid), .m_awready(l_awready),
    .m_wdata(l_wdata), .m_wstrb(l_wstrb), .m_wvalid(l_wvalid), .m_wready(l_wready),
    .m_bresp(l_bresp), .m_bvalid(l_bvalid), .m_bready(l_bready),
    .profile(cp_profile), .src_sel(cp_src), .thresh_sel(cp_thresh),
    .mute(cp_mute), .color_idx(cp_color), .decision_in(cp_decin),
    .loading(cp_loading)
  );
  assign status = {cp_thresh, cp_color, cp_mute, cp_loading, cp_profile};

  // --- 2:1 write mux: PS (boot setup) and the fabric loader share ppt_axi's one slave ---
  wire [7:0]  o_awaddr;
  wire        o_awvalid, o_awready, o_wvalid, o_wready, o_bvalid, o_bready;
  wire [31:0] o_wdata;
  wire [3:0]  o_wstrb;
  wire [1:0]  o_bresp;
  ppt_axi_wmux u_wmux (
    .clk(clk), .rst(~resetn),
    .s_awaddr(s_axi_awaddr), .s_awvalid(s_axi_awvalid), .s_awready(s_axi_awready),
    .s_wdata(s_axi_wdata), .s_wstrb(s_axi_wstrb), .s_wvalid(s_axi_wvalid), .s_wready(s_axi_wready),
    .s_bresp(s_axi_bresp), .s_bvalid(s_axi_bvalid), .s_bready(s_axi_bready),
    .m_awaddr(l_awaddr), .m_awvalid(l_awvalid), .m_awready(l_awready),
    .m_wdata(l_wdata), .m_wstrb(l_wstrb), .m_wvalid(l_wvalid), .m_wready(l_wready),
    .m_bresp(l_bresp), .m_bvalid(l_bvalid), .m_bready(l_bready),
    .o_awaddr(o_awaddr), .o_awvalid(o_awvalid), .o_awready(o_awready),
    .o_wdata(o_wdata), .o_wstrb(o_wstrb), .o_wvalid(o_wvalid), .o_wready(o_wready),
    .o_bresp(o_bresp), .o_bvalid(o_bvalid), .o_bready(o_bready)
  );

  // --- the finale front-end: shape the field in and the LED out, gated by the signed profile ---
  wire [11:0] eff_field;
  wire [5:0]  led_fc;
  wire [5:0]  dec_color_w;
  reg  [15:0] dec_target;
  reg         dec_valid;
  ppt_field_ctrl u_fc (
    .clk(clk), .rst(~resetn),
    .raw_pot(pot), .raw_band(band_field),
    .profile(cp_profile), .src_sel(cp_src), .thresh_sel(cp_thresh),
    .mute(cp_mute), .color_idx(cp_color), .decision_in(cp_decin),
    .dec_valid(dec_valid), .dec_color(dec_color_w),
    .eff_field(eff_field), .led_o(led_fc)
  );

  reg  fsm_fld_we, fsm_start;
  wire [15:0] fsm_fld_idx  = auto_pot_fidx;
  wire [1:0]  fsm_fld_type = TY_INT;
  wire [31:0] fsm_fld_val  = {20'd0, eff_field};

  // --- the resident band: cur_node is the stateful selector's one state cell, fabric-native ---
  // Stateless packs (AUTO_CTRL[1]=0, the reset default) bypass it entirely: fsm_node_idx =
  // auto_start_node, the certified path byte for byte. Reset-to migration: mid-swap (cp_loading)
  // parks the resident state on the SIGNED fail-safe, so an incomplete swap fails closed; a
  // completed swap ends with the incoming pack's replayed arm write, and the rising auto-live edge
  // performs the deliberate clean start from the incoming pack's signed start node.
  reg  [15:0] cur_node;
  reg         auto_live_d;
  wire        auto_live = auto_mode && !cp_loading;
  wire [15:0] fsm_node_idx = auto_stateful ? cur_node : auto_start_node;
  always @(posedge clk) begin
    if (!resetn) begin
      cur_node <= 16'd0; auto_live_d <= 1'b0;
    end else begin
      auto_live_d <= auto_live;
      if (auto_mode && cp_loading)        cur_node <= auto_safe_node;   // swap in flight: fail closed
      else if (!auto_mode)                cur_node <= auto_start_node;  // disarmed: parked on start
      else if (auto_live && !auto_live_d) cur_node <= auto_start_node;  // arm edge: deliberate start
      else if (auto_stateful && core_done && core_match)
                                          cur_node <= core_target;      // one step along a signed edge
    end
  end

  ppt_axi #(
    .MAX_FIELDS(MAX_FIELDS), .MAX_ATOMS(MAX_ATOMS), .MAX_NODES(MAX_NODES),
    .MAX_EDGES(MAX_EDGES), .MAX_PROG(MAX_PROG)
  ) axi (
    .s_axi_aclk(clk), .s_axi_aresetn(resetn),
    .s_axi_awaddr(o_awaddr), .s_axi_awvalid(o_awvalid), .s_axi_awready(o_awready),
    .s_axi_wdata(o_wdata), .s_axi_wstrb(o_wstrb), .s_axi_wvalid(o_wvalid),
    .s_axi_wready(o_wready), .s_axi_bresp(o_bresp), .s_axi_bvalid(o_bvalid),
    .s_axi_bready(o_bready), .s_axi_araddr(s_axi_araddr), .s_axi_arvalid(s_axi_arvalid),
    .s_axi_arready(s_axi_arready), .s_axi_rdata(s_axi_rdata), .s_axi_rresp(s_axi_rresp),
    .s_axi_rvalid(s_axi_rvalid), .s_axi_rready(s_axi_rready),
    .fsm_fld_we(fsm_fld_we), .fsm_fld_idx(fsm_fld_idx), .fsm_fld_type(fsm_fld_type),
    .fsm_fld_val(fsm_fld_val), .fsm_start(fsm_start), .fsm_node_idx(fsm_node_idx),
    .pot_now({4'd0, eff_field}),               // POT_NOW (0x2C) reflects the governed field
    .dbg_cur_node(cur_node),                   // CUR_NODE (0x30): the resident band, PS-readable
    .auto_mode(auto_mode), .auto_stateful(auto_stateful),
    .auto_start_node(auto_start_node), .auto_pot_fidx(auto_pot_fidx),
    .auto_safe_node(auto_safe_node),
    .core_busy(core_busy), .core_done(core_done), .core_match(core_match),
    .core_target(core_target),
    .o_load_en(o_load_en), .o_load_sel(o_load_sel), .o_load_addr(o_load_addr),
    .o_load_data(o_load_data)
  );

  // --- per-node color LUT (signed colors via load_sel==7, PS or loader alike) ---
  reg [5:0] node_color [MAX_NODES];
  integer i;
  always @(posedge clk) begin
    if (!resetn)
      for (i = 0; i < MAX_NODES; i = i + 1) node_color[i] <= 6'd0;
    else if (o_load_en && o_load_sel == 3'd7)
      node_color[o_load_addr[NB-1:0]] <= o_load_data[5:0];
  end
  assign dec_color_w = node_color[dec_target[NB-1:0]];

  // --- XADC DRP reader (unchanged) ---
  reg drp_st;
  assign drp_di  = 16'd0;
  assign drp_dwe = 1'b0;
  always @(posedge clk) begin
    drp_den <= 1'b0;
    if (!resetn) begin
      drp_st <= 1'b0; drp_daddr <= DADDR_VAUX1; pot <= 12'd0;
    end else case (drp_st)
      1'b0: begin drp_den <= 1'b1; drp_daddr <= DADDR_VAUX1; drp_st <= 1'b1; end
      1'b1: if (drp_drdy) begin pot <= drp_do[15:4]; drp_st <= 1'b0; end
    endcase
  end

  // --- evaluate FSM: pause while the loader is mid-swap so a policy never evaluates half-loaded ---
  reg  [1:0]  ev_st;
  always @(posedge clk) begin
    fsm_fld_we <= 1'b0;
    fsm_start  <= 1'b0;
    if (!resetn) begin
      ev_st <= 2'd0; dec_target <= 16'd0; dec_valid <= 1'b0;
    end else if (!auto_mode || cp_loading) begin
      ev_st <= 2'd0;
    end else case (ev_st)
      2'd0: begin fsm_fld_we <= 1'b1; ev_st <= 2'd1; end
      2'd1: begin fsm_start  <= 1'b1; ev_st <= 2'd2; end
      2'd2: if (core_done) begin
              dec_target <= core_target; dec_valid <= core_match; ev_st <= 2'd0;
            end
      default: ev_st <= 2'd0;
    endcase
  end

  // --- LED: auto -> the finale front-end's output; PS mode -> gpio_out ---
  assign led_o = auto_mode ? led_fc : ps_led;

endmodule

`default_nettype wire
