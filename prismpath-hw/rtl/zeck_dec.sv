// zeck_dec.sv — bit-serial Zeckendorf decoder: the receive half of Phase C2, the exact inverse of
// zeck_enc. Consumes a serial bit stream (the F2..Fk value bits ascending, closed by the self framing
// terminator "11") and emits one wire int per code. Same 32 bit datapath + F2..F46 ROM as the encoder,
// so decode(encode(n)) == n by construction, and the wire it reads is byte-identical to what the
// Python reference (packed.unpack -> zeckendorf.decode_stream) reads. No processor in the loop.
module zeck_dec #(
    parameter int W    = 32,
    parameter int NFIB = 45
)(
    input  logic         clk,
    input  logic         rst,
    input  logic         in_valid,   // 1 = in_bit carries a fresh serial bit this cycle
    input  logic         in_bit,     // the serial bit, same order zeck_enc emits: code[0..k] then 1
    output logic [W-1:0] out_val,    // decoded wire int, held; fresh when out_valid pulses
    output logic         out_valid,  // 1-cycle strobe: a complete code was terminated
    output logic         err         // 1-cycle strobe: a value bit fell past the ROM (oversized/malformed)
);
    // F2..F46 as an explicit constant ROM (see zeck_enc.sv: an initial-block loop zeroes fib[2..] on
    // silicon under Vivado though it simulates fine). Must match the encoder's table exactly.
    localparam logic [W-1:0] fib [0:NFIB-1] = '{
        32'd1, 32'd2, 32'd3, 32'd5, 32'd8,
        32'd13, 32'd21, 32'd34, 32'd55, 32'd89,
        32'd144, 32'd233, 32'd377, 32'd610, 32'd987,
        32'd1597, 32'd2584, 32'd4181, 32'd6765, 32'd10946,
        32'd17711, 32'd28657, 32'd46368, 32'd75025, 32'd121393,
        32'd196418, 32'd317811, 32'd514229, 32'd832040, 32'd1346269,
        32'd2178309, 32'd3524578, 32'd5702887, 32'd9227465, 32'd14930352,
        32'd24157817, 32'd39088169, 32'd63245986, 32'd102334155, 32'd165580141,
        32'd267914296, 32'd433494437, 32'd701408733, 32'd1134903170, 32'd1836311903
    };

    logic [W-1:0] acc;    // accumulated value of the code in flight
    logic [5:0]   i;      // Fibonacci index of the next bit (0 => F2)
    logic         prev;   // previous bit, for "11" terminator detection

    always_ff @(posedge clk) begin
        out_valid <= 1'b0;
        err       <= 1'b0;
        if (rst) begin
            acc  <= '0;
            i    <= 6'd0;
            prev <= 1'b0;
        end else if (in_valid) begin
            if (prev && in_bit) begin
                // "11": the second 1 is the terminator; the code accumulated so far is complete
                out_val   <= acc;
                out_valid <= 1'b1;
                acc  <= '0;
                i    <= 6'd0;
                prev <= 1'b0;
            end else begin
                if (in_bit) begin
                    if (i < NFIB[5:0]) acc <= acc + fib[i];
                    else               err <= 1'b1;   // set bit beyond the ROM: cannot represent
                end
                prev <= in_bit;
                i    <= i + 6'd1;
            end
        end
    end
endmodule
