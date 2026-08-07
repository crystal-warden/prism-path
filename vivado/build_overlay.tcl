# build_overlay.tcl — day-5 script for the Windows rig (Vivado 2023.2 batch mode):
#   vivado -mode batch -source build_overlay.tcl
# Produces build_overlay/ppt_overlay.bit + .hwh — the pair PYNQ's Overlay() loads.
#
# PS7 CONFIGURATION — READ FIRST. The Zynq PS block must match the Arty Z7-20 (DDR, clocks,
# MIO). The proven source of truth on this rig is the February design:
#   C:/Users/figue/CrystalWardenProject/Crystal_Warden_Core  (block design "warden_design")
# Before running this script, export its PS7 settings once:
#   open_project .../Crystal_Warden_Core.xpr
#   open_bd_design [get_files warden_design.bd]
#   write_bd_tcl -force ps7_from_feb.tcl        ;# then copy the PS7 CONFIG.* block into
#                                                ;# ps7_preset.tcl as `set ps7_cfg { ... }`
# If ps7_preset.tcl is absent this script falls back to Vivado's default PS7 automation,
# which boots under PYNQ (the SD image's FSBL owns early init) but leave a note in the log.

set here [file dirname [file normalize [info script]]]
set out $here/build_overlay
file mkdir $out

create_project -force ppt_overlay $out/proj -part xc7z020clg400-1
add_files [list $here/../rtl/ppt_interp.sv $here/../rtl/ppt_axi.sv $here/../rtl/ppt_axi_top.v]
set_property file_type SystemVerilog [get_files *.sv]

create_bd_design "ppt_bd"

# Zynq PS
set ps7 [create_bd_cell -type ip -vlnv xilinx.com:ip:processing_system7:5.5 ps7]
if {[file exists $here/ps7_preset.tcl]} {
  source $here/ps7_preset.tcl               ;# defines ps7_cfg from the Feb design
  set_property -dict $ps7_cfg $ps7
  puts "PS7: applied Feb-design preset"
} else {
  puts "PS7: WARNING — no ps7_preset.tcl; using default automation (PYNQ FSBL owns init)"
}
apply_bd_automation -rule xilinx.com:bd_rule:processing_system7 \
  -config {make_external "FIXED_IO, DDR" apply_board_preset "0"} $ps7
set_property -dict [list CONFIG.PCW_USE_M_AXI_GP0 {1} \
                         CONFIG.PCW_FPGA0_PERIPHERAL_FREQMHZ {50}] $ps7

# the interpreter, as an RTL module reference (no IP packaging ceremony)
set ppt [create_bd_cell -type module -reference ppt_axi_top ppt_0]

apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
  -config {Master "/ps7/M_AXI_GP0" intc_ip "New AXI Interconnect" Clk_xbar "Auto" \
           Clk_master "Auto" Clk_slave "Auto"} [get_bd_intf_pins ppt_0/s_axi]
assign_bd_address

validate_bd_design
add_files -norecurse [make_wrapper -files [get_files ppt_bd.bd] -top -force]
set_property top ppt_bd_wrapper [current_fileset]

# no board XDC needed: every external pin is PS-side (FIXED_IO/DDR are part-defined)
launch_runs synth_1 -jobs 8
wait_on_run synth_1
launch_runs impl_1 -to_step write_bitstream -jobs 8
wait_on_run impl_1

open_run impl_1
report_utilization -file $out/utilization.rpt
report_timing_summary -file $out/timing.rpt

file copy -force [get_property DIRECTORY [get_runs impl_1]]/ppt_bd_wrapper.bit \
  $out/ppt_overlay.bit
set hwh [glob -nocomplain $out/proj/*.gen/sources_1/bd/ppt_bd/hw_handoff/ppt_bd.hwh]
if {[llength $hwh] > 0} { file copy -force [lindex $hwh 0] $out/ppt_overlay.hwh }
puts "OVERLAY BUILD DONE: $out/ppt_overlay.bit (+ .hwh)"
