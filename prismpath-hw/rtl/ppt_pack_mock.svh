// ppt_pack_mock.svh - the sim-bringup mock pack (moved verbatim from ppt_pack_loader.sv).
// The real, compiler-generated pack is ppt_pack.svh (tools/gen_pack_svh.py); select it with
// `define PPT_PACK_REAL. The mock stays the default so the existing testbench vectors hold.
localparam int NPOL = 2;
localparam int NW   = 8;                    // total AXI writes across all policies
// each entry = {reg_addr[7:0], value[31:0]} ; regs: 0x20 soft-reset, 0x00 sel|addr, 0x04 data
localparam logic [39:0] WRITES [0:NW-1] = '{
    {8'h20, 32'h0000_0001},                             // policy 0: soft reset
    {8'h00, 32'h0001_0002}, {8'h04, 32'h0000_00C8},     //   sel1 addr2 <- 200
    {8'h00, 32'h0002_0003}, {8'h04, 32'h0000_01F4},     //   sel2 addr3 <- 500
    {8'h20, 32'h0000_0001},                             // policy 1: soft reset
    {8'h00, 32'h0007_0000}, {8'h04, 32'h0000_0002}      //   sel7 addr0 <- 2 (a color)
};
localparam int POL_START [0:NPOL-1] = '{0, 5};
localparam int POL_LEN   [0:NPOL-1] = '{5, 3};
