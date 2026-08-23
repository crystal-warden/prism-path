// ppt_axi_wmux.sv - a 2:1 AXI4-Lite WRITE-channel mux in front of ppt_axi's slave, so the same slave
// can be driven by either the PS (s_* : boot-time policy setup + colors) or the fabric pack loader
// (m_* : runtime hot-swaps), without the two colliding. The loader wins when both request (it only
// asserts during a human-paced button swap, and the PS is quiet then); the choice is latched for the
// whole transaction so a lagging W or B phase can't switch masters mid-write. The READ channel is not
// muxed - the loader never reads, so ppt_axi's AR/R stay wired to the PS. This is the one shared point
// where the standalone (fabric) and setup (PS) paths meet; everything downstream stays byte-identical.
`default_nettype none
module ppt_axi_wmux (
    input  wire        clk,
    input  wire        rst,
    // PS side (write channel)
    input  wire [7:0]  s_awaddr,
    input  wire        s_awvalid,
    output wire        s_awready,
    input  wire [31:0] s_wdata,
    input  wire [3:0]  s_wstrb,
    input  wire        s_wvalid,
    output wire        s_wready,
    output wire [1:0]  s_bresp,
    output wire        s_bvalid,
    input  wire        s_bready,
    // loader side (write channel)
    input  wire [7:0]  m_awaddr,
    input  wire        m_awvalid,
    output wire        m_awready,
    input  wire [31:0] m_wdata,
    input  wire [3:0]  m_wstrb,
    input  wire        m_wvalid,
    output wire        m_wready,
    output wire [1:0]  m_bresp,
    output wire        m_bvalid,
    input  wire        m_bready,
    // combined out -> ppt_axi slave
    output wire [7:0]  o_awaddr,
    output wire        o_awvalid,
    input  wire        o_awready,
    output wire [31:0] o_wdata,
    output wire [3:0]  o_wstrb,
    output wire        o_wvalid,
    input  wire        o_wready,
    input  wire [1:0]  o_bresp,
    input  wire        o_bvalid,
    output wire        o_bready
);
    // arbiter: latch the master for the whole transaction; loader has priority when idle
    reg busy, sel;                                  // sel: 0 = PS, 1 = loader
    always @(posedge clk) begin
        if (rst) begin
            busy <= 1'b0; sel <= 1'b0;
        end else if (!busy) begin
            if (m_awvalid)      begin sel <= 1'b1; busy <= 1'b1; end
            else if (s_awvalid) begin sel <= 1'b0; busy <= 1'b1; end
        end else if (o_bvalid && o_bready) begin
            busy <= 1'b0;
        end
    end

    wire csel = busy ? sel : m_awvalid;             // loader-priority in the idle cycle

    assign o_awaddr  = csel ? m_awaddr  : s_awaddr;
    assign o_awvalid = csel ? m_awvalid : s_awvalid;
    assign o_wdata   = csel ? m_wdata   : s_wdata;
    assign o_wstrb   = csel ? m_wstrb   : s_wstrb;
    assign o_wvalid  = csel ? m_wvalid  : s_wvalid;
    assign o_bready  = csel ? m_bready  : s_bready;

    assign m_awready = csel ? o_awready : 1'b0;
    assign s_awready = csel ? 1'b0      : o_awready;
    assign m_wready  = csel ? o_wready  : 1'b0;
    assign s_wready  = csel ? 1'b0      : o_wready;
    assign m_bvalid  = csel ? o_bvalid  : 1'b0;
    assign s_bvalid  = csel ? 1'b0      : o_bvalid;
    assign m_bresp   = o_bresp;
    assign s_bresp   = o_bresp;
endmodule
`default_nettype wire
