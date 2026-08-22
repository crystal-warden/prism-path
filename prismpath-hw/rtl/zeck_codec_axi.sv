// zeck_codec_axi.sv — AXI4-Lite face for the Phase C2 fabric codec (zeck_codec_core). The PS starts a
// run and reads the tallies; the encode/decode happen entirely in the PL. Register map (byte offsets):
//   0x00 R  MAGIC        = 0x5A434B31 ("ZCK1")
//   0x04 W  CTRL         [0] peek_go pulse, [1] selftest_go pulse
//   0x08 R  STATUS       [0] busy, [1] peek_done, [2] selftest_done, [3] dec_err
//   0x0C W  PEEK_IN      value n to encode+decode
//   0x10 W  SELFTEST_MAX sweep upper bound (n=1..MAX)
//   0x14 R  PEEK_BITS    encoded wire bits, first bit at MSB of the low PEEK_LEN bits
//   0x18 R  PEEK_LEN     number of encoded bits (incl the "11" terminator)
//   0x1C R  PEEK_DEC     in-fabric decode of those bits (== PEEK_IN on a good codec)
//   0x20 R  PASS_COUNT   self-test: count of decode(encode(n))==n
//   0x24 R  TOTAL        self-test: values swept
//   0x28 R  FIRST_FAIL   self-test: first n that mismatched, else 0
module zeck_codec_axi #(
    parameter int W    = 32,
    parameter int NFIB = 45
)(
    input  logic        clk,
    input  logic        resetn,
    input  logic [7:0]  s_axi_awaddr,
    input  logic        s_axi_awvalid,
    output logic        s_axi_awready,
    input  logic [31:0] s_axi_wdata,
    input  logic [3:0]  s_axi_wstrb,
    input  logic        s_axi_wvalid,
    output logic        s_axi_wready,
    output logic [1:0]  s_axi_bresp,
    output logic        s_axi_bvalid,
    input  logic        s_axi_bready,
    input  logic [7:0]  s_axi_araddr,
    input  logic        s_axi_arvalid,
    output logic        s_axi_arready,
    output logic [31:0] s_axi_rdata,
    output logic [1:0]  s_axi_rresp,
    output logic        s_axi_rvalid,
    input  logic        s_axi_rready
);
    logic rst;
    assign rst = ~resetn;

    // --- codec core ---
    logic          peek_go, selftest_go;
    logic [W-1:0]  peek_in, selftest_max;
    logic [W-1:0]  peek_bits, peek_dec, pass_count, total, first_fail;
    logic [6:0]    peek_len;
    logic          peek_done, selftest_done, dec_err, busy;
    logic          peek_done_s, selftest_done_s;

    zeck_codec_core #(.W(W), .NFIB(NFIB)) u_core (
        .clk(clk), .rst(rst),
        .peek_go(peek_go), .peek_in(peek_in), .peek_bits(peek_bits), .peek_len(peek_len),
        .peek_dec(peek_dec), .peek_done(peek_done),
        .selftest_go(selftest_go), .selftest_max(selftest_max),
        .pass_count(pass_count), .total(total), .first_fail(first_fail),
        .dec_err(dec_err), .selftest_done(selftest_done), .busy(busy)
    );

    // sticky done flags (the core pulses for one cycle; the PS polls STATUS)
    always_ff @(posedge clk) begin
        if (rst) begin
            peek_done_s <= 1'b0; selftest_done_s <= 1'b0;
        end else begin
            if (peek_go)          peek_done_s     <= 1'b0;
            else if (peek_done)   peek_done_s     <= 1'b1;
            if (selftest_go)      selftest_done_s <= 1'b0;
            else if (selftest_done) selftest_done_s <= 1'b1;
        end
    end

    // --- AXI4-Lite write channel (accept when address + data are both offered and no B pending) ---
    assign s_axi_awready = ~s_axi_bvalid & s_axi_awvalid & s_axi_wvalid;
    assign s_axi_wready  = s_axi_awready;

    always_ff @(posedge clk) begin
        peek_go     <= 1'b0;
        selftest_go <= 1'b0;
        if (rst) begin
            s_axi_bvalid <= 1'b0; s_axi_bresp <= 2'b00;
            peek_in <= '0; selftest_max <= '0;
        end else begin
            if (s_axi_awready) begin
                case (s_axi_awaddr)
                    8'h04: begin
                        if (s_axi_wdata[0]) peek_go     <= 1'b1;
                        if (s_axi_wdata[1]) selftest_go <= 1'b1;
                    end
                    8'h0C: peek_in      <= s_axi_wdata;
                    8'h10: selftest_max <= s_axi_wdata;
                    default: ;
                endcase
                s_axi_bvalid <= 1'b1; s_axi_bresp <= 2'b00;
            end else if (s_axi_bvalid && s_axi_bready) begin
                s_axi_bvalid <= 1'b0;
            end
        end
    end

    // --- AXI4-Lite read channel ---
    assign s_axi_arready = ~s_axi_rvalid;

    always_ff @(posedge clk) begin
        if (rst) begin
            s_axi_rvalid <= 1'b0; s_axi_rresp <= 2'b00; s_axi_rdata <= '0;
        end else begin
            if (s_axi_arready && s_axi_arvalid) begin
                s_axi_rvalid <= 1'b1; s_axi_rresp <= 2'b00;
                case (s_axi_araddr)
                    8'h00: s_axi_rdata <= 32'h5A434B31;
                    8'h08: s_axi_rdata <= {28'd0, dec_err, selftest_done_s, peek_done_s, busy};
                    8'h14: s_axi_rdata <= peek_bits;
                    8'h18: s_axi_rdata <= {25'd0, peek_len};
                    8'h1C: s_axi_rdata <= peek_dec;
                    8'h20: s_axi_rdata <= pass_count;
                    8'h24: s_axi_rdata <= total;
                    8'h28: s_axi_rdata <= first_fail;
                    default: s_axi_rdata <= 32'hDEADBEEF;
                endcase
            end else if (s_axi_rvalid && s_axi_rready) begin
                s_axi_rvalid <= 1'b0;
            end
        end
    end
endmodule
