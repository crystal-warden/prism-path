# build_overlay_finale.tcl — the pure-fabric control-plane finale overlay (arc #5).
# Board: Digilent Arty Z7-20 (xc7z020clg400-1), PYNQ image. Vivado 2023.2 batch:
#   vivado -mode batch -source build_overlay_finale.tcl
# Produces build_overlay_finale/ppt_finale.bit + .hwh.
#
# = build_overlay_zeck_demo (PS7 + zeck datapath + XADC DRP + gpio_out LED + IIC) PLUS:
#   - the fabric control plane (ctrl_in + ppt_ctrl_interp + ppt_pack_loader + ppt_axi_wmux +
#     ppt_field_ctrl) inside ppt_datapath_finale
#   - switches and ALL FOUR buttons as direct PL pins (gpio_in is gone; the fabric owns the controls)
#   - a cert-hook axi_gpio "gpio_dbg": ch1 8b OUT -> inj (OR into buttons/switches, scriptable
#     press), ch2 8b IN <- status {thresh[1:0], color[2:0], mute, loading, profile}
#   - PPT_PACK_REAL + PPT_CTRL_PACK_REAL: the compiler-generated SIGNED packs replace the mocks

set here [file dirname [file normalize [info script]]]
set out $here/build_overlay_finale
file mkdir $out

create_project -force ppt_finale $out/proj -part xc7z020clg400-1
add_files [list $here/../rtl/ppt_interp.sv $here/../rtl/ppt_axi.sv $here/../rtl/uart_rx.sv \
                $here/../rtl/zeck_dec.sv $here/../rtl/zeck_frame_rx.sv \
                $here/../rtl/ctrl_in.sv $here/../rtl/ppt_ctrl_interp.sv \
                $here/../rtl/ppt_pack_loader.sv $here/../rtl/ppt_ctrl_plane.sv \
                $here/../rtl/ppt_axi_wmux.sv $here/../rtl/ppt_field_ctrl.sv \
                $here/../rtl/ppt_datapath_finale.sv $here/../rtl/ppt_datapath_finale_top.v]
set_property file_type SystemVerilog [get_files *.sv]
# the generated signed packs are `include`d; Vivado's module-reference flow wants headers IN the
# project (filemgmt 56-591), typed as headers so they are not compiled as modules
add_files [list $here/../rtl/ppt_pack.svh $here/../rtl/ppt_ctrl_pack.svh \
                $here/../rtl/ppt_pack_mock.svh $here/../rtl/ppt_ctrl_pack_mock.svh]
set_property file_type {Verilog Header} [get_files *.svh]
set_property include_dirs [list $here/../rtl] [current_fileset]
set_property verilog_define [list PPT_PACK_REAL PPT_CTRL_PACK_REAL] [current_fileset]

create_bd_design "ppt_bd"

# --- Zynq PS (Feb-design preset) ---
set ps7 [create_bd_cell -type ip -vlnv xilinx.com:ip:processing_system7:5.5 ps7]
if {[file exists $here/ps7_preset.tcl]} {
  source $here/ps7_preset.tcl
  set_property -dict $ps7_cfg $ps7
  puts "PS7: applied Feb-design preset"
} else {
  puts "PS7: WARNING — no ps7_preset.tcl; using default automation (PYNQ FSBL owns init)"
}
apply_bd_automation -rule xilinx.com:bd_rule:processing_system7 \
  -config {make_external "FIXED_IO, DDR" apply_board_preset "0"} $ps7
set_property -dict [list CONFIG.PCW_USE_M_AXI_GP0 {1} \
                         CONFIG.PCW_FPGA0_PERIPHERAL_FREQMHZ {50}] $ps7

# --- the finale datapath (certified interp/axi + zeck decode + the fabric control plane) ---
create_bd_cell -type module -reference ppt_datapath_finale_top ppt_0

# --- PS-mode LED source (6b out, feeds ps_led; unchanged) ---
set gpio_out [create_bd_cell -type ip -vlnv xilinx.com:ip:axi_gpio:2.0 gpio_out]
set_property -dict [list CONFIG.C_IS_DUAL {0} \
  CONFIG.C_GPIO_WIDTH {6} CONFIG.C_ALL_OUTPUTS {1}] $gpio_out

# --- cert hooks: ch1 8b OUT = inj, ch2 8b IN = status ---
set gpio_dbg [create_bd_cell -type ip -vlnv xilinx.com:ip:axi_gpio:2.0 gpio_dbg]
set_property -dict [list CONFIG.C_IS_DUAL {1} \
  CONFIG.C_GPIO_WIDTH {8}  CONFIG.C_ALL_OUTPUTS {1} \
  CONFIG.C_GPIO2_WIDTH {8} CONFIG.C_ALL_INPUTS_2 {1}] $gpio_dbg

# --- I2C on PMOD-JA (kept wired, unused by the datapath) ---
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_iic:2.1 ja_iic

# --- XADC (pot on Vaux1, DRP-read by the fabric FSM) ---
set xadc [create_bd_cell -type ip -vlnv xilinx.com:ip:xadc_wiz:3.3 xadc]
set_property -dict [list \
  CONFIG.INTERFACE_SELECTION {Enable_DRP} \
  CONFIG.DCLK_FREQUENCY {50} \
  CONFIG.XADC_STARUP_SELECTION {channel_sequencer} \
  CONFIG.CHANNEL_ENABLE_VAUXP1_VAUXN1 {true} \
  CONFIG.SEQUENCER_MODE {Continuous} \
  CONFIG.ENABLE_RESET {false}] $xadc

# --- AXI slaves on PS7 M_AXI_GP0 ---
apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
  -config {Master "/ps7/M_AXI_GP0" intc_ip "New AXI Interconnect" \
           Clk_xbar "Auto" Clk_master "Auto" Clk_slave "Auto"} [get_bd_intf_pins ppt_0/s_axi]
foreach slave {gpio_out/S_AXI gpio_dbg/S_AXI ja_iic/S_AXI} {
  apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
    -config {Master "/ps7/M_AXI_GP0" intc_ip "Auto" \
             Clk_xbar "Auto" Clk_master "Auto" Clk_slave "Auto"} [get_bd_intf_pins $slave]
}

# --- XADC DRP <-> datapath (FCLK_CLK0 = 50 MHz) ---
connect_bd_net [get_bd_pins ppt_0/drp_den]   [get_bd_pins xadc/den_in]
connect_bd_net [get_bd_pins ppt_0/drp_daddr] [get_bd_pins xadc/daddr_in]
connect_bd_net [get_bd_pins ppt_0/drp_di]    [get_bd_pins xadc/di_in]
connect_bd_net [get_bd_pins ppt_0/drp_dwe]   [get_bd_pins xadc/dwe_in]
connect_bd_net [get_bd_pins xadc/do_out]     [get_bd_pins ppt_0/drp_do]
connect_bd_net [get_bd_pins xadc/drdy_out]   [get_bd_pins ppt_0/drp_drdy]
connect_bd_net [get_bd_pins xadc/dclk_in]    [get_bd_pins ps7/FCLK_CLK0]

# --- LED path ---
connect_bd_net [get_bd_pins gpio_out/gpio_io_o] [get_bd_pins ppt_0/ps_led]
connect_bd_net [get_bd_pins ppt_0/led_o] [create_bd_port -dir O -from 5 -to 0 led]

# --- controls: direct PL pins + cert hooks ---
connect_bd_net [get_bd_pins ppt_0/uart_rx_pin] [create_bd_port -dir I uart_rx_pin]
connect_bd_net [get_bd_pins ppt_0/btn_i] [create_bd_port -dir I -from 3 -to 0 btn_i]
connect_bd_net [get_bd_pins ppt_0/sw_i]  [create_bd_port -dir I -from 1 -to 0 sw_i]
connect_bd_net [get_bd_pins gpio_dbg/gpio_io_o]  [get_bd_pins ppt_0/inj]
connect_bd_net [get_bd_pins ppt_0/status] [get_bd_pins gpio_dbg/gpio2_io_i]

# --- external interface ports ---
connect_bd_intf_net [get_bd_intf_pins ja_iic/IIC] [create_bd_intf_port -mode Master -vlnv xilinx.com:interface:iic_rtl:1.0 ja_iic]
connect_bd_intf_net [get_bd_intf_pins xadc/Vaux1] [create_bd_intf_port -mode Slave  -vlnv xilinx.com:interface:diff_analog_io_rtl:1.0 Vaux1]

assign_bd_address
validate_bd_design

add_files -norecurse [make_wrapper -files [get_files ppt_bd.bd] -top -force]
set_property top ppt_bd_wrapper [current_fileset]
add_files -fileset constrs_1 -norecurse $here/finale.xdc

launch_runs synth_1 -jobs 8
wait_on_run synth_1
launch_runs impl_1 -to_step write_bitstream -jobs 8
wait_on_run impl_1

open_run impl_1
report_utilization -file $out/utilization.rpt
report_timing_summary -file $out/timing.rpt

file copy -force [get_property DIRECTORY [get_runs impl_1]]/ppt_bd_wrapper.bit $out/ppt_finale.bit
set hwh [glob -nocomplain $out/proj/*.gen/sources_1/bd/ppt_bd/hw_handoff/ppt_bd.hwh]
if {[llength $hwh] > 0} { file copy -force [lindex $hwh 0] $out/ppt_finale.hwh }
puts "FINALE OVERLAY BUILD DONE: $out/ppt_finale.bit (+ .hwh)"
