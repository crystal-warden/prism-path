// zeck_codec_core.sv — Phase C2 on silicon: zeck_enc + zeck_dec wired mouth-to-ear, with a control
// FSM that (a) PEEKs one value — encode n, capture the wire bits + length, decode them back — and
// (b) self-tests a sweep n=1..selftest_max entirely in the fabric, counting decode(encode(n))==n.
// No processor in the codec path; the PS only starts a run and reads the tallies. This is the module
// the AXI overlay wraps, and the module a cocotb round-trip test drives directly.
module zeck_codec_core #(
    parameter int W    = 32,
    parameter int NFIB = 45
)(
    input  logic          clk,
    input  logic          rst,
    // peek: encode+decode a single value; expose the wire it produced and the round-trip result
    input  logic          peek_go,
    input  logic [W-1:0]  peek_in,
    output logic [W-1:0]  peek_bits,     // encoded bits, first bit at MSB of the low peek_len bits
    output logic [6:0]    peek_len,      // number of encoded bits (incl the "11" terminator)
    output logic [W-1:0]  peek_dec,      // decode of those bits (== peek_in on a good codec)
    output logic          peek_done,
    // self-test: sweep n=1..selftest_max, count decode(encode(n))==n, all in the fabric
    input  logic          selftest_go,
    input  logic [W-1:0]  selftest_max,
    output logic [W-1:0]  pass_count,
    output logic [W-1:0]  total,
    output logic [W-1:0]  first_fail,    // first n that mismatched, else 0
    output logic          dec_err,       // sticky: a value bit fell past the ROM at some point
    output logic          selftest_done,
    output logic          busy
);
    // --- enc/dec instances, wired enc.out -> dec.in (the whole point: no processor between them) ---
    logic          e_in_valid, e_in_ready, e_out_valid, e_out_bit, e_done;
    logic [W-1:0]  e_in_val;
    logic          d_out_valid, d_err_pulse;
    logic [W-1:0]  d_out_val;

    zeck_enc #(.W(W), .NFIB(NFIB)) u_enc (
        .clk(clk), .rst(rst),
        .in_valid(e_in_valid), .in_val(e_in_val), .in_ready(e_in_ready),
        .out_valid(e_out_valid), .out_bit(e_out_bit), .done(e_done)
    );
    zeck_dec #(.W(W), .NFIB(NFIB)) u_dec (
        .clk(clk), .rst(rst),
        .in_valid(e_out_valid), .in_bit(e_out_bit),
        .out_val(d_out_val), .out_valid(d_out_valid), .err(d_err_pulse)
    );

    // --- per-value capture: shift enc bits in (first bit -> MSB of the used field), latch nothing else ---
    logic [W-1:0] cap_bits;
    logic [6:0]   cap_len;

    typedef enum logic [2:0] {IDLE, FEED, RUN, NEXT} st_t;
    st_t st;
    logic         mode_selftest;
    logic [W-1:0] cur;

    assign busy = (st != IDLE);

    always_ff @(posedge clk) begin
        peek_done     <= 1'b0;
        selftest_done <= 1'b0;
        e_in_valid    <= 1'b0;
        if (d_err_pulse) dec_err <= 1'b1;
        if (rst) begin
            st <= IDLE; pass_count <= '0; total <= '0; first_fail <= '0; dec_err <= 1'b0;
            cap_bits <= '0; cap_len <= '0;
            peek_bits <= '0; peek_len <= '0; peek_dec <= '0;
        end else begin
            case (st)
                IDLE: begin
                    if (peek_go) begin
                        mode_selftest <= 1'b0; cur <= peek_in;
                        cap_bits <= '0; cap_len <= '0;
                        st <= FEED;
                    end else if (selftest_go) begin
                        mode_selftest <= 1'b1; cur <= 32'd1;
                        pass_count <= '0; total <= '0; first_fail <= '0; dec_err <= 1'b0;
                        cap_bits <= '0; cap_len <= '0;
                        st <= FEED;
                    end
                end
                FEED: if (e_in_ready) begin       // hand the encoder the value (one-cycle in_valid pulse)
                    e_in_val   <= cur;
                    e_in_valid <= 1'b1;
                    st <= RUN;
                end
                RUN: begin
                    if (e_out_valid) begin        // stream the wire bits into the capture register
                        cap_bits <= (cap_bits << 1) | {{(W-1){1'b0}}, e_out_bit};
                        cap_len  <= cap_len + 7'd1;
                    end
                    if (d_out_valid) begin        // decode lands one cycle after the terminator bit;
                        if (!mode_selftest) begin  // by now cap_bits/cap_len already include that bit
                            peek_bits <= cap_bits;
                            peek_len  <= cap_len;
                            peek_dec  <= d_out_val;
                            peek_done <= 1'b1;
                            st <= IDLE;
                        end else begin
                            total <= total + 32'd1;
                            if (d_out_val == cur) pass_count <= pass_count + 32'd1;
                            else if (first_fail == '0) first_fail <= cur;
                            st <= NEXT;
                        end
                    end
                end
                NEXT: begin
                    if (cur >= selftest_max) begin
                        selftest_done <= 1'b1;
                        st <= IDLE;
                    end else begin
                        cur <= cur + 32'd1;
                        cap_bits <= '0; cap_len <= '0;
                        st <= FEED;
                    end
                end
                default: st <= IDLE;
            endcase
        end
    end
endmodule
