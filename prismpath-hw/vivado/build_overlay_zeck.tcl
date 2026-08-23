# build_overlay_zeck.tcl — Phase C2 codec overlay for the Windows rig (Vivado 2023.2 batch):
#   vivado -mode batch -source build_overlay_zeck.tcl
# Produces build_overlay_zeck/ppt_zeck.bit + .hwh — the pair PYNQ's Overlay() loads to MEASURE the
# native Zeckendorf codec (zeck_enc + zeck_dec, wired in the fabric) on the physical Zynq. PS-only
# design besides the codec's AXI slave; no board XDC (FIXED_IO/DDR are part-defined). See
# codec-bench/ for the reference corpus and results.

set here [file dirname [file normalize [info script]]]
set out $here/build_overlay_zeck
file mkdir $out

create_project -force ppt_zeck $out/proj -part xc7z020clg400-1
add_files [list $here/../rtl/zeck_enc.sv $here/../rtl/zeck_dec.sv \
                $here/../rtl/zeck_codec_core.sv $here/../rtl/zeck_codec_axi.sv \
                $here/../rtl/zeck_codec_top.v]
set_property file_type SystemVerilog [get_files *.sv]

create_bd_design "ppt_bd"

# Zynq PS (Feb-design preset)
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

# the fabric codec, as an RTL module reference
set zk [create_bd_cell -type module -reference zeck_codec_top ppt_0]

apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
  -config {Master "/ps7/M_AXI_GP0" intc_ip "New AXI Interconnect" Clk_xbar "Auto" \
           Clk_master "Auto" Clk_slave "Auto"} [get_bd_intf_pins ppt_0/s_axi]
assign_bd_address

validate_bd_design
add_files -norecurse [make_wrapper -files [get_files ppt_bd.bd] -top -force]
set_property top ppt_bd_wrapper [current_fileset]

launch_runs synth_1 -jobs 8
wait_on_run synth_1
launch_runs impl_1 -to_step write_bitstream -jobs 8
wait_on_run impl_1

open_run impl_1
report_utilization -file $out/utilization.rpt
report_timing_summary -file $out/timing.rpt

file copy -force [get_property DIRECTORY [get_runs impl_1]]/ppt_bd_wrapper.bit $out/ppt_zeck.bit
set hwh [glob -nocomplain $out/proj/*.gen/sources_1/bd/ppt_bd/hw_handoff/ppt_bd.hwh]
if {[llength $hwh] > 0} { file copy -force [lindex $hwh 0] $out/ppt_zeck.hwh }
puts "ZECK CODEC OVERLAY BUILD DONE: $out/ppt_zeck.bit (+ .hwh)"
