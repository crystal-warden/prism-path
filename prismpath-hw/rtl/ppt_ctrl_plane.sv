// ppt_ctrl_plane.sv - the fabric control plane: the control-interpreter wired to the pack loader. A
// button press runs through the signed control table (ppt_ctrl_interp) and, when the action is a
// hot-swap or meta-swap, kicks the loader (ppt_pack_loader) to replay that policy's load writes into
// ppt_axi's existing AXI4-Lite slave - the same writes the PS would issue, but with no processor. The
// datapath-facing outputs (profile, src_sel/thresh_sel, mute, color_idx, decision_in) carry the rest of
// the control state to the LED/field logic. Drop this next to ppt_axi and connect the AXI master port.
`default_nettype none
module ppt_ctrl_plane #(
    parameter int NBTN = 4,
    parameter int NSW  = 2
) (
    input  wire            clk,
    input  wire            rst,
    input  wire [NSW-1:0]  sw,
    input  wire [NBTN-1:0] btn_press,
    // AXI4-Lite master write channel -> ppt_axi slave
    output wire [7:0]      m_awaddr,
    output wire            m_awvalid,
    input  wire            m_awready,
    output wire [31:0]     m_wdata,
    output wire [3:0]      m_wstrb,
    output wire            m_wvalid,
    input  wire            m_wready,
    input  wire [1:0]      m_bresp,
    input  wire            m_bvalid,
    output wire            m_bready,
    // datapath / LED control
    output wire            profile,
    output wire [1:0]      src_sel,
    output wire [1:0]      thresh_sel,
    output wire            mute,
    output wire [2:0]      color_idx,
    output wire            decision_in,
    output wire            loading        // a policy load is in flight
);
    wire        lg;
    wire [7:0]  lp;
    wire        lbusy;

    ppt_ctrl_interp #(.NBTN(NBTN), .NSW(NSW)) u_ci (
        .clk(clk), .rst(rst),
        .sw(sw), .btn_press(btn_press), .ldr_busy(lbusy),
        .load_go(lg), .load_pol(lp),
        .profile(profile), .src_sel(src_sel), .thresh_sel(thresh_sel),
        .mute(mute), .color_idx(color_idx), .decision_in(decision_in)
    );

    ppt_pack_loader u_ld (
        .clk(clk), .rst(rst),
        .load_go(lg), .load_pol(lp), .busy(lbusy), .done(),
        .m_awaddr(m_awaddr), .m_awvalid(m_awvalid), .m_awready(m_awready),
        .m_wdata(m_wdata), .m_wstrb(m_wstrb), .m_wvalid(m_wvalid), .m_wready(m_wready),
        .m_bresp(m_bresp), .m_bvalid(m_bvalid), .m_bready(m_bready)
    );

    assign loading = lbusy;
endmodule
`default_nettype wire
