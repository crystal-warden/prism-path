# datapath.xdc — Stage-2 decision-datapath overlay pins, Digilent Arty Z7-20.
# Identical to pathb.xdc except the RGB LEDs are driven by the datapath's led_o (plain 6b output
# port `led`), not the gpio_out interface (rgb_tri_o). SW/BTN/I2C/analog are unchanged.
# Port names come from the external interfaces in build_overlay_datapath.tcl.

# switches: SW0/SW1 -> gpio_in ch1 (sw)
set_property -dict { PACKAGE_PIN M20 IOSTANDARD LVCMOS33 } [get_ports { sw_tri_i[0] }]
set_property -dict { PACKAGE_PIN M19 IOSTANDARD LVCMOS33 } [get_ports { sw_tri_i[1] }]

# buttons: BTN0/BTN1 -> gpio_in ch2 (btn)
set_property -dict { PACKAGE_PIN D19 IOSTANDARD LVCMOS33 } [get_ports { btn_tri_i[0] }]
set_property -dict { PACKAGE_PIN D20 IOSTANDARD LVCMOS33 } [get_ports { btn_tri_i[1] }]

# RGB LEDs -> datapath led_o (led): [0]=LED4_R [1]=LED4_G [2]=LED4_B [3]=LED5_R [4]=LED5_G [5]=LED5_B
set_property -dict { PACKAGE_PIN N15 IOSTANDARD LVCMOS33 } [get_ports { led[0] }]
set_property -dict { PACKAGE_PIN G17 IOSTANDARD LVCMOS33 } [get_ports { led[1] }]
set_property -dict { PACKAGE_PIN L15 IOSTANDARD LVCMOS33 } [get_ports { led[2] }]
set_property -dict { PACKAGE_PIN M15 IOSTANDARD LVCMOS33 } [get_ports { led[3] }]
set_property -dict { PACKAGE_PIN L14 IOSTANDARD LVCMOS33 } [get_ports { led[4] }]
set_property -dict { PACKAGE_PIN G14 IOSTANDARD LVCMOS33 } [get_ports { led[5] }]

# I2C on PMOD-JA (proven Feb pins): ToF + OLED share the bus
set_property -dict { PACKAGE_PIN Y19 IOSTANDARD LVCMOS33 } [get_ports { ja_iic_sda_io }]
set_property -dict { PACKAGE_PIN W19 IOSTANDARD LVCMOS33 } [get_ports { ja_iic_scl_io }]

# pot on ChipKit A0 -> XADC Vaux1 (CK_AN0_P/N)
set_property -dict { PACKAGE_PIN E17 IOSTANDARD LVCMOS33 } [get_ports { Vaux1_v_p }]
set_property -dict { PACKAGE_PIN D18 IOSTANDARD LVCMOS33 } [get_ports { Vaux1_v_n }]

# PL-native UART RX -> Pmod JA1 (Y18). Wire the ESP-NOW bridge ESP32: its UART TX -> JA1, GND -> JA GND.
#   The fabric's uart_rx recovers the byte (115200 8N1) and feeds it straight to the interpreter.
set_property -dict { PACKAGE_PIN Y18 IOSTANDARD LVCMOS33 } [get_ports { uart_rx_pin }]
