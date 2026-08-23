// ppt_pack_loader.sv - the pure-fabric hot-swap engine. On `load_go`, it replays a baked policy's load
// writes from a resident ROM into ppt_axi's EXISTING AXI4-Lite slave - byte-for-byte what the PS does
// over `load_image` - so the certified ppt_axi + ppt_interp stay untouched and their conformance carries.
// A fabric FSM is the master instead of the ARM: no processor loads the policy. The pack is a flat list
// of {reg, value} AXI writes (soft-reset + the sel/addr/data tuples the compiler emits per policy) with a
// per-policy {start,len} index; swapping = pointing the loader at a different index. The ROM here is a
// small MOCK; the compiler emits `ppt_pack.svh` (same shape) for the real signed pack.
`default_nettype none
module ppt_pack_loader (
    input  wire        clk,
    input  wire        rst,
    input  wire        load_go,        // pulse: load policy `load_pol`
    input  wire [7:0]  load_pol,
    output reg         busy,
    output reg         done,           // 1-cycle strobe when a load completes
    // AXI4-Lite master, write channel only -> ppt_axi slave
    output reg  [7:0]  m_awaddr,
    output reg         m_awvalid,
    input  wire        m_awready,
    output reg  [31:0] m_wdata,
    output wire [3:0]  m_wstrb,
    output reg         m_wvalid,
    input  wire        m_wready,
    input  wire [1:0]  m_bresp,
    input  wire        m_bvalid,
    output reg         m_bready
);
    assign m_wstrb = 4'hF;

    // ---- baked policy pack: the compiler-generated signed pack, or the sim-bringup mock ----
    // `define PPT_PACK_REAL selects tools/gen_pack_svh.py's output; default = mock (tb vectors hold).
`ifdef PPT_PACK_REAL
    `include "ppt_pack.svh"
`else
    `include "ppt_pack_mock.svh"
`endif
    localparam int LPW = (NPOL <= 1) ? 1 : $clog2(NPOL);   // policy-index width
    localparam int IW  = (NW  <= 1) ? 1 : $clog2(NW);      // write-index width

    typedef enum logic [1:0] {IDLE, REQ, RESP} st_t;
    st_t st;
    reg [15:0] idx;      // current write index into WRITES
    reg [15:0] rem;      // writes remaining in this policy

    always @(posedge clk) begin
        done <= 1'b0;
        if (rst) begin
            st <= IDLE; busy <= 1'b0;
            m_awvalid <= 1'b0; m_wvalid <= 1'b0; m_bready <= 1'b0;
        end else case (st)
            IDLE: begin
                busy <= 1'b0;
                if (load_go && load_pol < NPOL[7:0]) begin
                    idx  <= POL_START[load_pol[LPW-1:0]][15:0];
                    rem  <= POL_LEN[load_pol[LPW-1:0]][15:0];
                    busy <= 1'b1;
                    if (POL_LEN[load_pol[LPW-1:0]] == 0) begin done <= 1'b1; st <= IDLE; end
                    else st <= REQ;
                end
            end
            REQ: begin
                m_awaddr  <= WRITES[idx[IW-1:0]][39:32];
                m_wdata   <= WRITES[idx[IW-1:0]][31:0];
                m_awvalid <= 1'b1;
                m_wvalid  <= 1'b1;
                if (m_awready && m_wready) begin         // address + data both accepted
                    m_awvalid <= 1'b0;
                    m_wvalid  <= 1'b0;
                    m_bready  <= 1'b1;
                    st        <= RESP;
                end
            end
            RESP: if (m_bvalid) begin
                m_bready <= 1'b0;
                idx      <= idx + 16'd1;
                if (rem == 16'd1) begin
                    rem  <= 16'd0;
                    busy <= 1'b0;
                    done <= 1'b1;
                    st   <= IDLE;
                end else begin
                    rem <= rem - 16'd1;
                    st  <= REQ;
                end
            end
            default: st <= IDLE;
        endcase
    end
endmodule
`default_nettype wire
