// ppt_field_ctrl.sv - the finale datapath front-end: it applies the control-plane's outputs to the
// field going INTO the interpreter and to the LED coming OUT, without touching the certified interp.
//   Act 1  (profile 0): field = the selected sensor source (pot / walker); LED = the decided color.
//   Finale (profile 1): the same field, but modified by the finale's controls -
//     * mute        : freeze the field at its last live value (LED looks dead, like unplugged)
//     * thresh_sel  : bias the field so the SAME signed policy renders a higher severity baseline
//     * decision_in : BTN2 arms a governed decision; the switch-selected severity picks the verdict
//     * color_idx   : override the LED through all colors (idx 0 = back to the live decision color)
// The interp still decides on whatever field this hands it; this only shapes the input and the output,
// so the policy remains the authority. Finale-only effects are gated by `profile`, so leaving the
// finale (meta-swap back to Act 1) restores the plain live loop even if the finale state is still set.
`default_nettype none
module ppt_field_ctrl (
    input  wire        clk,
    input  wire        rst,
    input  wire [11:0] raw_pot,      // XADC pot field
    input  wire [11:0] raw_band,     // walker's fabric-decoded band field
    // control-plane outputs
    input  wire        profile,      // 0 = Act 1, 1 = Finale
    input  wire [1:0]  src_sel,      // 0 = pot, 1 = walker (2 = mesh, reserved -> pot)
    input  wire [1:0]  thresh_sel,   // finale severity baseline: 0 low, 1/2 caution, 3 severe
    input  wire        mute,         // finale: freeze the field
    input  wire [2:0]  color_idx,    // finale: LED color override (0 = live decision color)
    input  wire        decision_in,  // finale: 1-cycle strobe, step the injected decision field
    // interp decision (for LED pass-through)
    input  wire        dec_valid,
    input  wire [5:0]  dec_color,
    // outputs
    output wire [11:0] eff_field,    // -> the interpreter's field
    output wire [5:0]  led_o
);
    // ---- source select (switches in Act 1; frozen at last value once in the finale) ----
    wire [11:0] live = (src_sel == 2'd1) ? raw_band : raw_pot;

    // ---- mute: hold the last live value while muted (finale only) ----
    reg [11:0] frozen;
    always @(posedge clk)
        if (rst)        frozen <= 12'd0;
        else if (!mute) frozen <= live;
    wire [11:0] sensed = (profile && mute) ? frozen : live;

    // ---- decision input: BTN2 arms a governed decision. While armed, the field is a fixed reference,
    //      so the verdict is decided purely by the switch-selected severity (the bias below): low ref
    //      alone -> low band, ref+caution -> mid band, ref+severe -> high band. Press again to release
    //      back to the live sensor. SW can be swept while armed to walk the verdicts at that input. ----
    localparam [11:0] DEC_REF = 12'd200;    // reference input; the severity bias lifts it into a band
    reg armed;
    always @(posedge clk)
        if (rst)                         armed <= 1'b0;
        else if (profile && decision_in) armed <= ~armed;
    wire [11:0] base = (profile && armed) ? DEC_REF : sensed;

    // ---- severity baseline: bias the field up so the same policy cuts read more severe (finale) ----
    reg [11:0] bias;
    always @* begin
        if (!profile)               bias = 12'd0;
        else case (thresh_sel)
            2'd0:    bias = 12'd0;      // low  - as authored
            2'd3:    bias = 12'd1600;   // severe
            default: bias = 12'd600;    // caution
        endcase
    end
    wire [12:0] sum = {1'b0, base} + {1'b0, bias};
    assign eff_field = sum[12] ? 12'hFFF : sum[11:0];   // clamp to 12-bit

    // ---- LED: finale color-override (idx 1..7) else the live decision color ----
    wire [5:0] decision_led = dec_valid ? dec_color : 6'd0;
    reg  [2:0] c;                                        // {B,G,R}
    always @* case (color_idx)
        3'd1:    c = 3'b001;   // red
        3'd2:    c = 3'b010;   // green
        3'd3:    c = 3'b100;   // blue
        3'd4:    c = 3'b011;   // yellow
        3'd5:    c = 3'b110;   // cyan
        3'd6:    c = 3'b101;   // magenta
        3'd7:    c = 3'b111;   // white
        default: c = 3'b000;   // 0 -> off (unused; idx 0 means "live decision" below)
    endcase
    assign led_o = (profile && color_idx != 3'd0) ? {c, c} : decision_led;
endmodule
`default_nettype wire
