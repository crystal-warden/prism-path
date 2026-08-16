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
    logic [W-1:0] fib [NFIB];
    initial begin
        fib[0] = 32'd1;
        fib[1] = 32'd2;
        for (int j = 2; j < NFIB; j++) fib[j] = fib[j-1] + fib[j-2];
    end

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
