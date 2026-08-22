// zeck_frame_rx.sv — decode the walker's Facet band frame straight off a UART byte stream, IN THE
// FABRIC. The wire is the spiral-mesh frame: zeck [class+1, tick+1, band+1], packed MSB-first into
// bytes. This feeds each byte bit-serially (MSB first) into zeck_dec, counts three codes, and emits
// band = code[2]-1. Frames are self-delimited by the idle gap between the walker's bursts: after
// GAP_TICKS idle cycles the decoder is held in reset, so the next byte realigns to a frame's first
// bit. No processor decodes the wire — this is what makes the walker demo natively PL-decoded.
`default_nettype none
module zeck_frame_rx #(
    parameter int GAP_TICKS = 50_000     // idle cycles that end a frame (~1ms @50MHz; >> the ~87us
                                          // intra-frame byte spacing, << the walker's inter-frame gap)
)(
    input  wire        clk,
    input  wire        rst,
    input  wire        byte_valid,       // strobe from uart_rx
    input  wire [7:0]  byte_in,
    output reg  [2:0]  band,             // 0..4, last decoded
    output reg         band_valid        // 1-cycle strobe when a full frame's band lands
);
    reg  [7:0]  sh;
    reg  [3:0]  nbits;
    reg  [24:0] idle;
    wire        gap = (idle >= GAP_TICKS[24:0]);

    reg         fed_valid, fed_bit;
    wire        dec_rst = rst | gap;      // hold the decoder reset through the whole inter-frame gap
    wire [31:0] code_val;
    wire        code_valid;
    zeck_dec #(.W(32), .NFIB(45)) u_dec (
        .clk(clk), .rst(dec_rst),
        .in_valid(fed_valid), .in_bit(fed_bit),
        .out_val(code_val), .out_valid(code_valid), .err()
    );

    reg [1:0] code_idx;                   // 0=class+1, 1=tick+1, 2=band+1

    always @(posedge clk) begin
        fed_valid  <= 1'b0;
        band_valid <= 1'b0;
        if (rst) begin
            sh <= 8'd0; nbits <= 4'd0; idle <= {25{1'b1}}; code_idx <= 2'd0; band <= 3'd0;
        end else begin
            // idle timer (saturates at GAP_TICKS)
            if (byte_valid)                   idle <= 25'd0;
            else if (idle < GAP_TICKS[24:0])  idle <= idle + 1'b1;

            if (gap) code_idx <= 2'd0;        // realign: next frame starts at code 0

            // load a byte, then clock its bits out MSB-first (never during a gap)
            if (byte_valid) begin
                sh <= byte_in; nbits <= 4'd8;
            end else if (nbits != 4'd0 && !gap) begin
                fed_valid <= 1'b1;
                fed_bit   <= sh[7];
                sh        <= {sh[6:0], 1'b0};
                nbits     <= nbits - 1'b1;
            end

            // collect the three codes; the third (band+1) yields band
            if (code_valid && !gap) begin
                case (code_idx)
                    2'd0: code_idx <= 2'd1;
                    2'd1: code_idx <= 2'd2;
                    2'd2: begin
                        band       <= (code_val != 32'd0) ? (code_val[2:0] - 3'd1) : 3'd0;
                        band_valid <= 1'b1;
                        code_idx   <= 2'd0;
                    end
                    default: code_idx <= 2'd0;
                endcase
            end
        end
    end
endmodule
`default_nettype wire
