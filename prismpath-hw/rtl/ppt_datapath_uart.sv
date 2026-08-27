// ppt_datapath_uart.sv — PL-native UART variant of the decision datapath. Same fabric loop
// (field -> ppt_interp -> per-node color -> RGB LEDs, PS out of the hot path), but the field value
// arrives from a UART receiver IN THE FABRIC (an ESP-NOW bridge's byte on a Pmod pin) instead of the
// XADC pot. Once a UART byte has been seen the field follows it; until then it follows the pot, so
// the knob still works standalone. Decode + decide + light happen entirely in the PL, no processor.

`default_nettype none

module ppt_datapath_uart #(
  parameter int MAX_FIELDS = 16,
  parameter int MAX_ATOMS  = 64,
  parameter int MAX_NODES  = 16,
  parameter int MAX_EDGES  = 48,
  parameter int MAX_PROG   = 256
)(
  input  wire        clk,
  input  wire        resetn,
  // AXI4-Lite slave (PS face — passed straight to ppt_axi)
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
  // XADC DRP master (read-only): reads Vaux1 status register continuously
  output reg         drp_den,
  output reg  [6:0]  drp_daddr,
  output wire [15:0] drp_di,
  output wire        drp_dwe,
  input  wire [15:0] drp_do,
  input  wire        drp_drdy,
  // LEDs: ps_led from the gpio_out IP (PS mode); led_o to the RGB pins
  input  wire [5:0]  ps_led,
  output wire [5:0]  led_o,
  // PL-native UART RX: the ESP-NOW bridge's serial (115200 8N1) straight into the fabric
  input  wire        uart_rx_pin
);

  localparam [6:0] DADDR_VAUX1 = 7'h11;      // XADC status reg for VAUXP1/VAUXN1
  localparam [1:0] TY_INT      = 2'd2;
  localparam int   NB          = (MAX_NODES <= 1) ? 1 : $clog2(MAX_NODES);

  // --- hooks to/from ppt_axi ---
  wire        auto_mode;
  wire [15:0] auto_start_node, auto_pot_fidx;
  wire        core_done, core_match, core_busy;
  wire [15:0] core_target;
  wire        o_load_en;
  wire [2:0]  o_load_sel;
  wire [15:0] o_load_addr;
  wire [31:0] o_load_data;

  reg  [11:0] pot;                            // latest Vaux1 (12-bit)

  // --- PL-native UART: recover the bridge's byte in the fabric, scale to the field range, latch ---
  wire [7:0] uart_byte;
  wire       uart_valid;
  reg  [11:0] uart_val;
  reg         uart_seen;
  uart_rx #(.CLK_HZ(50_000_000), .BAUD(115200)) u_rx (
    .clk(clk), .rst(~resetn), .rx(uart_rx_pin), .data(uart_byte), .valid(uart_valid)
  );
  always @(posedge clk) begin
    if (!resetn) begin uart_val <= 12'd0; uart_seen <= 1'b0; end
    else if (uart_valid) begin uart_val <= {uart_byte, 4'd0}; uart_seen <= 1'b1; end  // byte*16 -> 0..4080
  end

  reg         fsm_fld_we, fsm_start;
  wire [11:0] fld_sel      = uart_seen ? uart_val : pot;   // UART takes over once a byte lands; pot until then
  wire [15:0] fsm_fld_idx  = auto_pot_fidx;
  wire [1:0]  fsm_fld_type = TY_INT;
  wire [31:0] fsm_fld_val  = {20'd0, fld_sel};
  wire [15:0] fsm_node_idx = auto_start_node;

  ppt_axi #(
    .MAX_FIELDS(MAX_FIELDS), .MAX_ATOMS(MAX_ATOMS), .MAX_NODES(MAX_NODES),
    .MAX_EDGES(MAX_EDGES), .MAX_PROG(MAX_PROG)
  ) axi (
    .s_axi_aclk(clk), .s_axi_aresetn(resetn),
    .s_axi_awaddr(s_axi_awaddr), .s_axi_awvalid(s_axi_awvalid), .s_axi_awready(s_axi_awready),
    .s_axi_wdata(s_axi_wdata), .s_axi_wstrb(s_axi_wstrb), .s_axi_wvalid(s_axi_wvalid),
    .s_axi_wready(s_axi_wready), .s_axi_bresp(s_axi_bresp), .s_axi_bvalid(s_axi_bvalid),
    .s_axi_bready(s_axi_bready), .s_axi_araddr(s_axi_araddr), .s_axi_arvalid(s_axi_arvalid),
    .s_axi_arready(s_axi_arready), .s_axi_rdata(s_axi_rdata), .s_axi_rresp(s_axi_rresp),
    .s_axi_rvalid(s_axi_rvalid), .s_axi_rready(s_axi_rready),
    .fsm_fld_we(fsm_fld_we), .fsm_fld_idx(fsm_fld_idx), .fsm_fld_type(fsm_fld_type),
    .fsm_fld_val(fsm_fld_val), .fsm_start(fsm_start), .fsm_node_idx(fsm_node_idx),
    .pot_now({4'd0, fld_sel}),                 // POT_NOW (0x2C) reflects the ACTUAL field (UART or pot)
    .auto_mode(auto_mode), .auto_start_node(auto_start_node), .auto_pot_fidx(auto_pot_fidx),
    .core_busy(core_busy), .core_done(core_done), .core_match(core_match),
    .core_target(core_target),
    .o_load_en(o_load_en), .o_load_sel(o_load_sel), .o_load_addr(o_load_addr),
    .o_load_data(o_load_data)
  );

  // --- per-node color LUT: loaded from the signed table via load_sel==7 (the compiler's colors) ---
  reg [5:0] node_color [MAX_NODES];
  integer i;
  always @(posedge clk) begin
    if (!resetn)
      for (i = 0; i < MAX_NODES; i = i + 1) node_color[i] <= 6'd0;
    else if (o_load_en && o_load_sel == 3'd7)
      node_color[o_load_addr[NB-1:0]] <= o_load_data[5:0];
  end

  // --- XADC DRP reader: continuously read Vaux1, latch the 12-bit result ---
  reg drp_st;
  assign drp_di  = 16'd0;
  assign drp_dwe = 1'b0;                      // read-only
  always @(posedge clk) begin
    drp_den <= 1'b0;
    if (!resetn) begin
      drp_st <= 1'b0; drp_daddr <= DADDR_VAUX1; pot <= 12'd0;
    end else case (drp_st)
      1'b0: begin drp_den <= 1'b1; drp_daddr <= DADDR_VAUX1; drp_st <= 1'b1; end
      1'b1: if (drp_drdy) begin pot <= drp_do[15:4]; drp_st <= 1'b0; end
    endcase
  end

  // --- evaluate FSM: write pot field -> pulse start -> latch the fabric's decision ---
  reg  [1:0]  ev_st;
  reg  [15:0] dec_target;
  reg         dec_valid;
  always @(posedge clk) begin
    fsm_fld_we <= 1'b0;
    fsm_start  <= 1'b0;
    if (!resetn) begin
      ev_st <= 2'd0; dec_target <= 16'd0; dec_valid <= 1'b0;
    end else if (!auto_mode) begin
      ev_st <= 2'd0;                          // idle in PS mode
    end else case (ev_st)
      2'd0: begin fsm_fld_we <= 1'b1; ev_st <= 2'd1; end
      2'd1: begin fsm_start  <= 1'b1; ev_st <= 2'd2; end
      2'd2: if (core_done) begin
              dec_target <= core_target; dec_valid <= core_match; ev_st <= 2'd0;
            end
      default: ev_st <= 2'd0;
    endcase
  end

  // --- LED mux: auto -> color of the decided node (off if stuck); PS mode -> gpio_out ---
  wire [5:0] auto_led = dec_valid ? node_color[dec_target[NB-1:0]] : 6'd0;
  assign led_o = auto_mode ? auto_led : ps_led;

endmodule

`default_nettype wire
