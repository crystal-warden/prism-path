// zeck_enc.sv — bit-serial Zeckendorf encoder: the shift register half of Phase C2.
// Bit-exact with the reference wire (zeckendorf.encode_stream -> packed.pack(bits, 8)):
// for a wire int n >= 1, emit the bits for F2..Fk ascending, then a terminator 1 (the
// self framing "11"). Symbols are cell indices, small by construction, so a 32 bit
// datapath (F2..F46 ROM) is generous; the 2^53 figure is the VALUE domain upstream of
// quantization, never the symbol domain this encoder sees.
module zeck_enc #(
    parameter int W    = 32,
    parameter int NFIB = 45
)(
    input  logic         clk,
    input  logic         rst,
    input  logic         in_valid,
    input  logic [W-1:0] in_val,
    output logic         in_ready,
    output logic         out_valid,
    output logic         out_bit,
    output logic         done
);
    // F2..F46 as an explicit constant ROM. NOTE: an initial-block loop (fib[j]=fib[j-1]+fib[j-2])
    // simulates correctly but Vivado evaluates the RHS against the un-updated array, zeroing fib[2..]
    // on silicon — so the table is written out. (NFIB must stay 45 to match this pattern.)
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

    typedef enum logic [1:0] {IDLE, SCAN, MARK, EMIT} st_t;
    st_t st;
    logic [W-1:0] rem;
    logic [5:0] k, i;
    logic [NFIB-1:0] code;

    assign in_ready = (st == IDLE) && !rst;

    always_ff @(posedge clk) begin
        out_valid <= 1'b0;
        done      <= 1'b0;
        if (rst) begin
            st <= IDLE;
        end else begin
            case (st)
                IDLE: if (in_valid && in_val != '0) begin
                    rem  <= in_val;
                    k    <= 6'd0;
                    code <= '0;
                    st   <= SCAN;
                end
                SCAN: if ((k + 6'd1) < NFIB[5:0] && fib[k + 6'd1] <= rem) begin
                    k <= k + 6'd1;
                end else begin
                    i  <= k;
                    st <= MARK;
                end
                MARK: begin
                    if (fib[i] <= rem) begin
                        code[i] <= 1'b1;
                        rem     <= rem - fib[i];
                    end
                    if (i == 6'd0) begin
                        st <= EMIT;
                    end else begin
                        i <= i - 6'd1;
                    end
                end
                EMIT: begin
                    out_valid <= 1'b1;
                    if (i <= k) begin
                        out_bit <= code[i];
                        i       <= i + 6'd1;
                    end else begin
                        out_bit <= 1'b1;
                        done    <= 1'b1;
                        st      <= IDLE;
                    end
                end
                default: st <= IDLE;
            endcase
        end
    end
endmodule
