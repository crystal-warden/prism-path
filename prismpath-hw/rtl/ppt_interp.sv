// ppt_interp.sv — the PPT v1 table-image interpreter: a FIXED circuit that routes any
// conformant Level M flow loaded as DATA through the load port. Never re-synthesized per
// flow — the flow stays data all the way down (TABLE_FORMAT.md is the contract; interp.c
// is the behavioral twin this module is diffed against under cocotb).
//
// Evaluate protocol: host writes the field register file (one write per field), pulses
// `start` with `node_idx`; `done` pulses with `match`/`match_edge`/`target`. A node's
// ordered edges are tried first-true-wins (the priority encoder); each edge's boolean
// program runs on a tiny 1-bit stack machine, one word per cycle; atoms are combinational
// comparators over the field registers.
//
// `visits` is a per-node saturating counter bank owned by the fabric: `bump_en` increments
// on node entry (engine: before the worker), and when `use_visits` is high an atom reading
// the header's visits field sees the current node's counter — the engine's
// `ctx = {**fields, "visits": n}` in silicon. `use_visits` low = raw register file
// (the C target's eval mode).

`default_nettype none

module ppt_interp #(
  parameter int MAX_FIELDS = 16,
  parameter int MAX_ATOMS  = 64,
  parameter int MAX_NODES  = 16,
  parameter int MAX_EDGES  = 48,
  parameter int MAX_PROG   = 256,
  parameter int STACK_D    = 16
)(
  input  wire        clk,
  input  wire        rst,          // sync, active high: clears visits + field types

  // table load port (the "BRAM image" write path; AXI-Lite fronts this on the board)
  //   sel 0: header  — addr 0: visits_idx
  //   sel 1: atoms   — {ty[7:0], op[7:0], field[15:0]}
  //   sel 2: atoms   — const val (signed 32)
  //   sel 3: nodes   — {edge_cnt[15:0], edge_off[15:0]}
  //   sel 4: edges   — {prog_off[15:0], target[15:0]}
  //   sel 5: edges   — prog_cnt[15:0]
  //   sel 6: prog    — program word[15:0]
  input  wire        load_en,
  input  wire [2:0]  load_sel,
  input  wire [15:0] load_addr,
  input  wire [31:0] load_data,

  // field register file write port
  input  wire        fld_we,
  input  wire [15:0] fld_idx,
  input  wire [1:0]  fld_type,     // 0 none / 1 bool / 2 int / 3 str(intern id)
  input  wire [31:0] fld_val,

  // visits counter bank
  input  wire        bump_en,
  input  wire [15:0] bump_node,
  input  wire        use_visits,

  // evaluate
  input  wire        start,
  input  wire [15:0] node_idx,
  output reg         busy,
  output reg         done,         // 1-cycle pulse
  output reg         match,        // valid with done; 0 = no edge matched (stuck/terminal)
  output reg  [15:0] match_edge,
  output reg  [15:0] target
);

  localparam logic [1:0] TY_NONE = 2'd0, TY_BOOL = 2'd1, TY_INT = 2'd2, TY_STR = 2'd3;
  localparam logic [15:0] OPC_NOT   = 16'h8000,
                          OPC_AND   = 16'h8001,
                          OPC_OR    = 16'h8002,
                          OPC_TRUE  = 16'h8003,
                          OPC_FALSE = 16'h8004;
  localparam logic [15:0] VISITS_NONE = 16'hFFFF;

  // ------------------------------------------------------------------ table storage
  reg [15:0]        visits_idx;
  reg [15:0]        atom_field [MAX_ATOMS];
  reg [7:0]         atom_op    [MAX_ATOMS];
  reg [1:0]         atom_ty    [MAX_ATOMS];
  reg signed [31:0] atom_val   [MAX_ATOMS];
  reg [15:0]        node_eoff  [MAX_NODES];
  reg [15:0]        node_ecnt  [MAX_NODES];
  reg [15:0]        edge_tgt   [MAX_EDGES];
  reg [15:0]        edge_poff  [MAX_EDGES];
  reg [15:0]        edge_pcnt  [MAX_EDGES];
  reg [15:0]        prog       [MAX_PROG];

  // ------------------------------------------------------------------ runtime state
  reg [1:0]         f_ty [MAX_FIELDS];
  reg signed [31:0] f_v  [MAX_FIELDS];
  reg [15:0]        visits [MAX_NODES];

  always @(posedge clk) begin
    if (load_en) begin
      case (load_sel)
        3'd0: visits_idx <= load_data[15:0];
        3'd1: begin
          atom_field[load_addr[$clog2(MAX_ATOMS)-1:0]] <= load_data[15:0];
          atom_op   [load_addr[$clog2(MAX_ATOMS)-1:0]] <= load_data[23:16];
          atom_ty   [load_addr[$clog2(MAX_ATOMS)-1:0]] <= load_data[25:24];
        end
        3'd2: atom_val [load_addr[$clog2(MAX_ATOMS)-1:0]]  <= load_data;
        3'd3: begin
          node_eoff[load_addr[$clog2(MAX_NODES)-1:0]] <= load_data[15:0];
          node_ecnt[load_addr[$clog2(MAX_NODES)-1:0]] <= load_data[31:16];
        end
        3'd4: begin
          edge_tgt [load_addr[$clog2(MAX_EDGES)-1:0]] <= load_data[15:0];
          edge_poff[load_addr[$clog2(MAX_EDGES)-1:0]] <= load_data[31:16];
        end
        3'd5: edge_pcnt[load_addr[$clog2(MAX_EDGES)-1:0]] <= load_data[15:0];
        3'd6: prog     [load_addr[$clog2(MAX_PROG)-1:0]]  <= load_data[15:0];
        default: ;
      endcase
    end
    if (fld_we)
      begin
        f_ty[fld_idx[$clog2(MAX_FIELDS)-1:0]] <= fld_type;
        f_v [fld_idx[$clog2(MAX_FIELDS)-1:0]] <= fld_val;
      end
    if (bump_en && visits[bump_node[$clog2(MAX_NODES)-1:0]] != 16'hFFFF)
      visits[bump_node[$clog2(MAX_NODES)-1:0]]
        <= visits[bump_node[$clog2(MAX_NODES)-1:0]] + 16'd1;
    if (rst) begin
      for (int i = 0; i < MAX_NODES; i++)  visits[i] <= 16'd0;
      for (int i = 0; i < MAX_FIELDS; i++) f_ty[i]   <= TY_NONE;
    end
  end

  // ------------------------------------------------------------------ the atom comparator
  // One of these per referenced atom exists conceptually in parallel; v0 evaluates the
  // program's current word, so one comparator is instantiated and indexed.
  function automatic logic atom_true(input logic [15:0] ai);
    logic [$clog2(MAX_ATOMS)-1:0] a;
    logic [1:0]         rty;
    logic signed [31:0] rv;
    logic [1:0]         cty;
    logic signed [31:0] cv;
    logic lnum, rnum, eq;
    begin
      a = ai[$clog2(MAX_ATOMS)-1:0];
      if (use_visits && visits_idx != VISITS_NONE && atom_field[a] == visits_idx) begin
        rty = TY_INT;
        rv  = {16'd0, visits[node_r[$clog2(MAX_NODES)-1:0]]};
      end else begin
        rty = f_ty[atom_field[a][$clog2(MAX_FIELDS)-1:0]];
        rv  = f_v [atom_field[a][$clog2(MAX_FIELDS)-1:0]];
      end
      cty  = atom_ty[a][1:0];
      cv   = atom_val[a];
      lnum = (rty == TY_BOOL) || (rty == TY_INT);
      rnum = (cty == TY_BOOL) || (cty == TY_INT);
      if (lnum && rnum)                       eq = (rv == cv);
      else if (rty == TY_STR && cty == TY_STR) eq = (rv == cv);
      else if (rty == TY_NONE && cty == TY_NONE) eq = 1'b1;
      else                                    eq = 1'b0;
      case (atom_op[a])
        8'd0: atom_true = eq;                                   // ==
        8'd1: atom_true = !eq;                                  // !=
        8'd2: atom_true = (lnum && rnum) ? (rv <  cv) : 1'b0;   // <   (totality: else false)
        8'd3: atom_true = (lnum && rnum) ? (rv <= cv) : 1'b0;   // <=
        8'd4: atom_true = (lnum && rnum) ? (rv >  cv) : 1'b0;   // >
        8'd5: atom_true = (lnum && rnum) ? (rv >= cv) : 1'b0;   // >=
        8'd6: atom_true = (rty == TY_NONE) ? 1'b0 : (rv != 32'sd0);  // truthy
        default: atom_true = 1'b0;
      endcase
    end
  endfunction

  // ------------------------------------------------------------------ the evaluate FSM
  typedef enum logic [1:0] { S_IDLE, S_EDGE, S_RUN, S_DONE } state_t;
  state_t st;

  reg [15:0] node_r;
  reg [15:0] cur_edge;      // index within the node's edge list
  reg [15:0] pc;            // index within the current edge's program
  reg [STACK_D-1:0] stk;    // 1-bit stack, stk[0] = top after final word
  reg [$clog2(STACK_D):0] sp;

  wire [15:0] eidx  = node_eoff[node_r[$clog2(MAX_NODES)-1:0]] + cur_edge;
  wire [15:0] paddr = edge_poff[eidx[$clog2(MAX_EDGES)-1:0]] + pc;
  wire [15:0] pword = prog[paddr[$clog2(MAX_PROG)-1:0]];

  always @(posedge clk) begin
    done <= 1'b0;
    if (rst) begin
      st <= S_IDLE; busy <= 1'b0; match <= 1'b0;
    end else begin
      case (st)
        S_IDLE: if (start) begin
          node_r <= node_idx; cur_edge <= 16'd0; busy <= 1'b1; st <= S_EDGE;
        end
        S_EDGE: begin
          if (cur_edge >= node_ecnt[node_r[$clog2(MAX_NODES)-1:0]]) begin
            match <= 1'b0; st <= S_DONE;          // no edge matched (stuck / terminal)
          end else begin
            pc <= 16'd0; sp <= '0; st <= S_RUN;
          end
        end
        S_RUN: begin
          if (pword < 16'h8000) begin             // push atom result
            stk <= {stk[STACK_D-2:0], atom_true(pword)};
            sp  <= sp + 1'b1;
          end else case (pword)
            OPC_NOT:   stk[0] <= !stk[0];
            OPC_AND:   begin stk <= {1'b0, stk[STACK_D-1:1]}; stk[0] <= stk[1] && stk[0];
                             sp <= sp - 1'b1; end
            OPC_OR:    begin stk <= {1'b0, stk[STACK_D-1:1]}; stk[0] <= stk[1] || stk[0];
                             sp <= sp - 1'b1; end
            OPC_TRUE:  begin stk <= {stk[STACK_D-2:0], 1'b1}; sp <= sp + 1'b1; end
            OPC_FALSE: begin stk <= {stk[STACK_D-2:0], 1'b0}; sp <= sp + 1'b1; end
            default: ;
          endcase
          if (pc + 16'd1 >= edge_pcnt[eidx[$clog2(MAX_EDGES)-1:0]])
            st <= S_DONE;                          // result lands in stk[0] next cycle
          else
            pc <= pc + 16'd1;
        end
        S_DONE: begin
          // entered from S_RUN (ran=1: this edge's result is in stk[0]) or from S_EDGE
          // with the edge list exhausted (ran=0)
          if (ran && !stk[0] &&
              cur_edge + 16'd1 < node_ecnt[node_r[$clog2(MAX_NODES)-1:0]]) begin
            cur_edge <= cur_edge + 16'd1; st <= S_EDGE;   // priority encoder: next edge
          end else begin
            match      <= ran && stk[0];
            match_edge <= cur_edge;
            target     <= edge_tgt[eidx[$clog2(MAX_EDGES)-1:0]];
            busy <= 1'b0; done <= 1'b1; st <= S_IDLE;
          end
        end
        default: st <= S_IDLE;
      endcase
    end
  end

  reg ran;
  always @(posedge clk) begin
    if (rst) ran <= 1'b0;
    else if (st == S_EDGE) ran <= 1'b0;
    else if (st == S_RUN)  ran <= 1'b1;
  end

`ifdef FORMAL
  // ---------------------------------------------------------------- WCET formal property
  // For any VALID table (the only kind we ever sign + load), `done` follows an accepted `start`
  // within N_MAX cycles. Per-evaluate cost = 2*E + P + 2 (E=node edges, P=its edges' total program
  // words), calibrated on the RTL in tb/wcet. The envelope bound at the synthesized caps:
  // True universal worst case is 3E+P (not 2E+P): every edge costs >=1 S_RUN cycle even with a
  // zero-word program, so an adversarial table adds up to one extra cycle per edge. 2E+P is the
  // bound for REAL policies (every edge's program >=1 word); this is the bound for ANY valid table.
  localparam int N_MAX = 3*MAX_EDGES + MAX_PROG + 8;   // 408 at 48/256

  // every trace starts from reset: clean control state, table arbitrary but count-bounded below
  reg fv_reset_done = 1'b0;
  always @(posedge clk) fv_reset_done <= 1'b1;
  always @* if (!fv_reset_done) assume (rst);

  integer fvk;
  reg [31:0] fv_ecnt_total, fv_pcnt_total;
  reg        fv_nodes_ok;
  always @* begin
    fv_ecnt_total = 0;
    for (fvk = 0; fvk < MAX_NODES; fvk = fvk + 1) fv_ecnt_total = fv_ecnt_total + node_ecnt[fvk];
    fv_pcnt_total = 0;
    for (fvk = 0; fvk < MAX_EDGES; fvk = fvk + 1) fv_pcnt_total = fv_pcnt_total + edge_pcnt[fvk];
    // every node's edge range stays within the edge array (what validate_image enforces): keeps the
    // FSM's edge index in [0, MAX_EDGES), so what it reads is what fv_pcnt_total actually sums.
    fv_nodes_ok = 1'b1;
    for (fvk = 0; fvk < MAX_NODES; fvk = fvk + 1)
      if (node_eoff[fvk] + node_ecnt[fvk] > MAX_EDGES) fv_nodes_ok = 1'b0;
  end

  reg [15:0] fv_cnt;
  reg        fv_watch;
  always @(posedge clk) begin
    // validity: exactly what validate_image enforces on every shipped image (total edges + total
    // program words within the caps), plus the protocol invariant (no table reload mid-evaluate).
    assume (fv_ecnt_total <= MAX_EDGES);
    assume (fv_pcnt_total <= MAX_PROG);
    assume (fv_nodes_ok);
    // no table reload across an evaluate (the whole watch window + the start cycle). Keyed off
    // fv_watch, not busy, so it holds even in the induction's arbitrary states. Matches the protocol:
    // the PS loads the table, THEN pulses start; the two never coincide.
    if (fv_watch || (start && st == S_IDLE)) assume (!load_en);

    if (rst) begin
      fv_watch <= 1'b0; fv_cnt <= 16'd0;
    end else if (start && st == S_IDLE) begin
      fv_watch <= 1'b1; fv_cnt <= 16'd0;
    end else if (fv_watch) begin
      fv_cnt <= fv_cnt + 16'd1;
      if (done) fv_watch <= 1'b0;
    end

    if (!rst && fv_watch) assert (fv_cnt <= N_MAX);   // never exceed the bound before done pulses
    // strengthening: watch is only high mid-evaluate (busy) or at the done pulse — rules out the
    // phantom watch=1/busy=0 states the induction step would otherwise explore.
    if (!rst) assert (!fv_watch || busy || done);
    // strengthening: idle-while-watching is only ever the done-pulse cycle (else fv_cnt could grow
    // in a phantom idle state where the ranking function below is 0).
    if (!rst) assert (!(fv_watch && st == S_IDLE) || done);
    // strengthenings that pin the walk to the table (in-range work; also excludes the 16-bit
    // cur_edge+1 wraparound the induction otherwise exploits from garbage states):
    if (!rst && fv_watch && st != S_IDLE) assert (cur_edge <= fv_ecnt);
    if (!rst && fv_watch && st == S_RUN) begin
      assert (cur_edge < fv_ecnt);
      assert ((fv_pcur == 0 && pc == 0) || pc < fv_pcur);
    end
    // the ranking invariant: counted cycles + worst-case cycles remaining never exceed the bound.
    // R is a pure function of the current state, so induction only checks per-transition arithmetic.
    if (!rst && fv_watch) assert ({16'd0, fv_cnt} + fv_R <= N_MAX);
  end

  // --- ranking function R: worst-case cycles until the done pulse, from the CURRENT state.
  //     Computed combinationally from the FSM state and the table's count arrays (bounded loops) —
  //     the prover never has to invent a sum, only verify that R decreases every watched cycle. ---
  wire [15:0] fv_ecnt = node_ecnt[node_r[$clog2(MAX_NODES)-1:0]];
  wire [15:0] fv_eoff = node_eoff[node_r[$clog2(MAX_NODES)-1:0]];
  wire [15:0] fv_pcur = edge_pcnt[eidx[$clog2(MAX_EDGES)-1:0]];

  // sum over future edges of (wmax(p_j) + 2), iterated over ABSOLUTE array positions so every
  // edge_pcnt read has a CONSTANT index per unrolled iteration (no mux trees in the SMT formula —
  // the variable-index form was the solver bottleneck). Same set: j-eoff in (cur_edge, ecnt).
  integer fvj;
  reg [31:0] fv_fut, fv_lo, fv_hi;
  always @* begin
    fv_lo  = {16'd0, fv_eoff} + {16'd0, cur_edge} + 32'd1;   // 32-bit math: no 16-bit wraparound
    fv_hi  = {16'd0, fv_eoff} + {16'd0, fv_ecnt};
    fv_fut = 0;
    for (fvj = 0; fvj < MAX_EDGES; fvj = fvj + 1)
      if (fvj >= fv_lo && fvj < fv_hi)
        fv_fut = fv_fut + ((edge_pcnt[fvj] == 0) ? 32'd3 : (edge_pcnt[fvj] + 32'd2));
  end

  wire [31:0] fv_rdone = (cur_edge + 16'd1 < fv_ecnt) ? (32'd1 + fv_fut) : 32'd1;
  reg [31:0] fv_R;
  always @* begin
    case (st)
      S_IDLE: fv_R = 32'd0;                                             // only the done-pulse cycle
      S_EDGE: fv_R = (cur_edge >= fv_ecnt) ? 32'd2                      // exhaustion: DONE, done
                     : (32'd1 + ((fv_pcur == 0) ? 32'd1 : {16'd0, fv_pcur}) + fv_rdone);
      S_RUN:  fv_R = ((fv_pcur == 0) ? 32'd1 : ({16'd0, fv_pcur} - {16'd0, pc})) + fv_rdone;
      S_DONE: fv_R = fv_rdone;
      default: fv_R = 32'd0;
    endcase
  end
`endif

endmodule

`default_nettype wire
