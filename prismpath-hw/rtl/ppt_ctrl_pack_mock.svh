// ppt_ctrl_pack_mock.svh - the sim-bringup control table (moved verbatim from ppt_ctrl_interp.sv).
// The real, compiler-generated table is ppt_ctrl_pack.svh (tools/gen_pack_svh.py from
// ctrl_table.json); select it with `define PPT_CTRL_PACK_REAL. Mock stays the default.
// entry = {act_code[2:0], act_arg[7:0]} ; index = profile*NBTN + btn
// A_SWAP arg = decision-policy index to load.   A_META arg = {new_profile[7], pack_index[6:0]}.
localparam int NENT = 2*NBTN;
localparam logic [10:0] CTRL_TBL [0:NENT-1] = '{
    {A_SWAP,  8'd0},          // P0 BTN0 -> hot-swap to decision policy 0
    {A_SWAP,  8'd1},          // P0 BTN1 -> hot-swap to decision policy 1
    {A_SWAP,  8'd2},          // P0 BTN2 -> hot-swap to decision policy 2
    {A_META,  8'b1_0000001},  // P0 BTN3 -> meta-swap: profile<=1, load pack 1 (finale)
    {A_COLOR, 8'd0},          // P1 BTN0 -> cycle all LED colors
    {A_MUTE,  8'd0},          // P1 BTN1 -> mute / unmute the sensor
    {A_DECIN, 8'd0},          // P1 BTN2 -> decision input
    {A_META,  8'b0_0000000}   // P1 BTN3 -> meta-swap exit: profile<=0, load pack 0 (Act 1)
};
