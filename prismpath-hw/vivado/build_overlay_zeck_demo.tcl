# build_overlay_datapath.tcl — Stage-2 "decision datapath" overlay for the live fabric demo.
# Board: Digilent Arty Z7-20 (xc7z020clg400-1) running the PYNQ image.
#   vivado -mode batch -source build_overlay_datapath.tcl
# Produces build_overlay_datapath/ppt_datapath.bit + .hwh — the pair PYNQ's Overlay() loads.
#
# Difference from build_overlay_pathb.tcl: the interpreter cell is ppt_datapath_top (ppt_axi + the
# untouched ppt_interp + the fabric FSM). In auto_mode the PL closes the whole loop with the PS out
# of the hot path:
#   - XADC reads Vaux1 (pot) over its DRP port -> the datapath FSM (NOT AXI anymore; PS reads POT_NOW)
#   - the FSM writes the pot field, pulses evaluate, drives the RGB LEDs from the SIGNED per-node color
#   - auto_mode=0 (reset default) is byte-identical to the pathb (PS-driven) overlay
# gpio_out still exists (PS-mode LED source -> ps_led); the datapath's led_o drives the RGB pins.
# Pins: datapath.xdc (= pathb.xdc with the RGB port renamed rgb_tri_o -> led).

set here [file dirname [file normalize [info script]]]
set out $here/build_overlay_zeck_demo
file mkdir $out

create_project -force ppt_datapath_zeck $out/proj -part xc7z020clg400-1
add_files [list $here/../rtl/ppt_interp.sv $here/../rtl/ppt_axi.sv $here/../rtl/uart_rx.sv \
                $here/../rtl/zeck_dec.sv $here/../rtl/zeck_frame_rx.sv \
                $here/../rtl/ppt_datapath_zeck.sv $here/../rtl/ppt_datapath_zeck_top.v]
set_property file_type SystemVerilog [get_files *.sv]

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

# --- the decision datapath (ppt_axi + ppt_interp + fabric FSM + color LUT + LED mux) ---
create_bd_cell -type module -reference ppt_datapath_zeck_top ppt_0

# --- bench I/O IP ---
# inputs: ch1 = switches (2b in), ch2 = buttons (2b in)
set gpio_in [create_bd_cell -type ip -vlnv xilinx.com:ip:axi_gpio:2.0 gpio_in]
set_property -dict [list CONFIG.C_IS_DUAL {1} \
  CONFIG.C_GPIO_WIDTH {2}  CONFIG.C_ALL_INPUTS {1} \
  CONFIG.C_GPIO2_WIDTH {2} CONFIG.C_ALL_INPUTS_2 {1}] $gpio_in

# PS-mode LED source: 6b out. NOT externalized — its gpio_io_o feeds the datapath's ps_led.
set gpio_out [create_bd_cell -type ip -vlnv xilinx.com:ip:axi_gpio:2.0 gpio_out]
set_property -dict [list CONFIG.C_IS_DUAL {0} \
  CONFIG.C_GPIO_WIDTH {6} CONFIG.C_ALL_OUTPUTS {1}] $gpio_out

# I2C on PMOD-JA (ToF + OLED share the bus, distinct addresses) — unused by the datapath, kept wired
create_bd_cell -type ip -vlnv xilinx.com:ip:axi_iic:2.1 ja_iic

# XADC — pot on ChipKit A0 = Vaux1, read over DRP by the datapath FSM (continuous sequencer).
# INIT attrs from these settings configure the XADC at power-up; the FSM only reads status reg 0x11.
set xadc [create_bd_cell -type ip -vlnv xilinx.com:ip:xadc_wiz:3.3 xadc]
# DCLK_FREQUENCY MUST match the clock we feed dclk_in (FCLK_CLK0 = 50 MHz) so the IP picks the right
# ADC clock divider. Default was 100 -> at 50 MHz it converted at ~half rate (~2us/sample); 50 -> ~1us.
set_property -dict [list \
  CONFIG.INTERFACE_SELECTION {Enable_DRP} \
  CONFIG.DCLK_FREQUENCY {50} \
  CONFIG.XADC_STARUP_SELECTION {channel_sequencer} \
  CONFIG.CHANNEL_ENABLE_VAUXP1_VAUXN1 {true} \
  CONFIG.SEQUENCER_MODE {Continuous} \
  CONFIG.ENABLE_RESET {false}] $xadc

# --- AXI slaves on PS7 M_AXI_GP0 (ppt_0 creates the interconnect; gpio/iic reuse it). XADC is DRP,
#     not an AXI slave anymore. ---
apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
  -config {Master "/ps7/M_AXI_GP0" intc_ip "New AXI Interconnect" \
           Clk_xbar "Auto" Clk_master "Auto" Clk_slave "Auto"} [get_bd_intf_pins ppt_0/s_axi]
foreach slave {gpio_in/S_AXI gpio_out/S_AXI ja_iic/S_AXI} {
  apply_bd_automation -rule xilinx.com:bd_rule:axi4 \
    -config {Master "/ps7/M_AXI_GP0" intc_ip "Auto" \
             Clk_xbar "Auto" Clk_master "Auto" Clk_slave "Auto"} [get_bd_intf_pins $slave]
}

# --- XADC DRP <-> datapath FSM (same clock domain: FCLK_CLK0 = 50 MHz) ---
connect_bd_net [get_bd_pins ppt_0/drp_den]   [get_bd_pins xadc/den_in]
connect_bd_net [get_bd_pins ppt_0/drp_daddr] [get_bd_pins xadc/daddr_in]
connect_bd_net [get_bd_pins ppt_0/drp_di]    [get_bd_pins xadc/di_in]
connect_bd_net [get_bd_pins ppt_0/drp_dwe]   [get_bd_pins xadc/dwe_in]
connect_bd_net [get_bd_pins xadc/do_out]     [get_bd_pins ppt_0/drp_do]
connect_bd_net [get_bd_pins xadc/drdy_out]   [get_bd_pins ppt_0/drp_drdy]
connect_bd_net [get_bd_pins xadc/dclk_in]    [get_bd_pins ps7/FCLK_CLK0]

# --- LED path: PS-mode gpio_out -> ps_led; datapath led_o -> RGB pins ---
connect_bd_net [get_bd_pins gpio_out/gpio_io_o] [get_bd_pins ppt_0/ps_led]
connect_bd_net [get_bd_pins ppt_0/led_o] [create_bd_port -dir O -from 5 -to 0 led]

# --- PL-native UART RX -> Pmod pin (the ESP-NOW bridge's serial into the fabric; pin in uart.xdc) ---
connect_bd_net [get_bd_pins ppt_0/uart_rx_pin] [create_bd_port -dir I uart_rx_pin]

# --- external interface ports (deterministic names the XDC matches) ---
connect_bd_intf_net [get_bd_intf_pins gpio_in/GPIO]  [create_bd_intf_port -mode Master -vlnv xilinx.com:interface:gpio_rtl:1.0 sw]
connect_bd_intf_net [get_bd_intf_pins gpio_in/GPIO2] [create_bd_intf_port -mode Master -vlnv xilinx.com:interface:gpio_rtl:1.0 btn]
connect_bd_intf_net [get_bd_intf_pins ja_iic/IIC]    [create_bd_intf_port -mode Master -vlnv xilinx.com:interface:iic_rtl:1.0 ja_iic]
connect_bd_intf_net [get_bd_intf_pins xadc/Vaux1]    [create_bd_intf_port -mode Slave  -vlnv xilinx.com:interface:diff_analog_io_rtl:1.0 Vaux1]

assign_bd_address
validate_bd_design

add_files -norecurse [make_wrapper -files [get_files ppt_bd.bd] -top -force]
set_property top ppt_bd_wrapper [current_fileset]
add_files -fileset constrs_1 -norecurse $here/uart.xdc

launch_runs synth_1 -jobs 8
wait_on_run synth_1
launch_runs impl_1 -to_step write_bitstream -jobs 8
wait_on_run impl_1

open_run impl_1
report_utilization -file $out/utilization.rpt
report_timing_summary -file $out/timing.rpt

file copy -force [get_property DIRECTORY [get_runs impl_1]]/ppt_bd_wrapper.bit $out/ppt_datapath_zeck.bit
set hwh [glob -nocomplain $out/proj/*.gen/sources_1/bd/ppt_bd/hw_handoff/ppt_bd.hwh]
if {[llength $hwh] > 0} { file copy -force [lindex $hwh 0] $out/ppt_datapath_zeck.hwh }
puts "ZECK DEMO OVERLAY BUILD DONE: $out/ppt_datapath_zeck.bit (+ .hwh)"
