// ppt_ctrl_interp.sv - the control-interpreter: a second, tiny match-action interpreter whose "policy"
// is a signed control table mapping (profile, button) -> action. A signed `ctrl_mode` field selects
// which of two baked profiles is live, so even what the buttons DO is governed by signed policy, not
// hand-wired gates. Profile 0 (Act 1): switches pick the sensor source; BTN0-2 hot-swap the decision
// policy (via the fabric pack loader); BTN3 meta-swaps into the finale. Profile 1 (Finale): switches
// pick the severity baseline; BTN0 cycles LED colors; BTN1 mutes the sensor; BTN2 injects a decision;
// BTN3 meta-swaps back. The meta-swap (BTN3) flips the profile AND kicks the loader to install the new
// mode's decision policy - so one button changes what every other button means. The table here is a
// MOCK; the compiler emits `ppt_ctrl_pack.svh` (same shape) as part of the signed pack.
`default_nettype none
module ppt_ctrl_interp #(
    parameter int NBTN = 4,          // must be a power of two (table is indexed {profile, btn})
    parameter int NSW  = 2
) (
    input  wire            clk,
    input  wire            rst,
    input  wire [NSW-1:0]  sw,          // debounced switch level  (from ctrl_in)
    input  wire [NBTN-1:0] btn_press,   // one-shot press strobes   (from ctrl_in)
    input  wire            ldr_busy,    // pack loader is mid-load  (from ppt_pack_loader.busy)
    // -> pack loader
    output reg             load_go,     // 1-cycle strobe: load policy `load_pol`
    output reg  [7:0]      load_pol,
    // -> datapath / LED
    output reg             profile,     // 0 = Act 1, 1 = Finale  (== signed ctrl_mode)
    output reg  [1:0]      src_sel,     // profile 0: sensor source  (pot / walker / mesh)
    output reg  [1:0]      thresh_sel,  // profile 1: severity baseline (low / caution / severe)
    output reg             mute,        // profile 1: freeze the sensor field
    output reg  [2:0]      color_idx,   // profile 1: cycled LED color
    output reg             decision_in  // profile 1: decision-input strobe
);
    // ---- action codes ----
    localparam logic [2:0] A_NOP=3'd0, A_SWAP=3'd1, A_META=3'd2,
                           A_COLOR=3'd3, A_MUTE=3'd4, A_DECIN=3'd5;

    // ---- baked signed control table: compiler-generated, or the sim-bringup mock ----
    // `define PPT_CTRL_PACK_REAL selects tools/gen_pack_svh.py's ppt_ctrl_pack.svh; default = mock.
`ifdef PPT_CTRL_PACK_REAL
    `include "ppt_ctrl_pack.svh"
`else
    `include "ppt_ctrl_pack_mock.svh"
`endif
    localparam int TBW = (NBTN <= 1) ? 1 : $clog2(NBTN);

    // priority-select the lowest asserted button this cycle
    reg [TBW-1:0] bsel;
    reg           bhit;
    integer bi;
    always @* begin
        bhit = 1'b0; bsel = '0;
        for (bi = NBTN-1; bi >= 0; bi = bi - 1)
            if (btn_press[bi]) begin bhit = 1'b1; bsel = bi[TBW-1:0]; end
    end

    wire [10:0] ent  = CTRL_TBL[{profile, bsel}];   // profile*NBTN + bsel (NBTN a power of two)
    wire [2:0]  code = ent[10:8];
    wire [7:0]  arg  = ent[7:0];

    always @(posedge clk) begin
        load_go     <= 1'b0;                 // strobes default low
        decision_in <= 1'b0;
        if (rst) begin
            profile <= 1'b0; mute <= 1'b0; color_idx <= 3'd0;
            load_pol <= 8'd0; src_sel <= 2'd0; thresh_sel <= 2'd0;
        end else begin
            if (!profile) src_sel <= sw[1:0];    // switches mean sensor-source in Act 1 ...
            else          thresh_sel <= sw[1:0]; // ... and severity-baseline in the finale
            if (bhit) case (code)
                A_SWAP:  if (!ldr_busy) begin load_go <= 1'b1; load_pol <= arg; end
                A_META:  if (!ldr_busy) begin
                             profile  <= arg[7];
                             load_go  <= 1'b1;
                             load_pol <= {1'b0, arg[6:0]};
                         end
                A_COLOR: color_idx   <= color_idx + 3'd1;
                A_MUTE:  mute        <= ~mute;
                A_DECIN: decision_in <= 1'b1;
                default: ;   // A_NOP
            endcase
        end
    end
endmodule
`default_nettype wire
