# finale.xdc — fabric-control-plane finale overlay pins, Digilent Arty Z7-20.
# Same as uart.xdc except the switches and ALL FOUR buttons are direct PL ports (sw_i / btn_i) into
# the fabric control plane; the PS gpio_in channels are gone. Port names come from
# build_overlay_finale.tcl's external ports.

# switches: SW0/SW1 -> PL (ctrl_in)
set_property -dict { PACKAGE_PIN M20 IOSTANDARD LVCMOS33 } [get_ports { sw_i[0] }]
set_property -dict { PACKAGE_PIN M19 IOSTANDARD LVCMOS33 } [get_ports { sw_i[1] }]

# buttons: BTN0-BTN3 -> PL (ctrl_in)   (Arty Z7-20 master XDC: D19 D20 L20 L19)
set_property -dict { PACKAGE_PIN D19 IOSTANDARD LVCMOS33 } [get_ports { btn_i[0] }]
set_property -dict { PACKAGE_PIN D20 IOSTANDARD LVCMOS33 } [get_ports { btn_i[1] }]
set_property -dict { PACKAGE_PIN L20 IOSTANDARD LVCMOS33 } [get_ports { btn_i[2] }]
set_property -dict { PACKAGE_PIN L19 IOSTANDARD LVCMOS33 } [get_ports { btn_i[3] }]

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

# PL-native UART RX -> Pmod JA1 (Y18): ESP-NOW bridge TX -> JA1, GND -> JA GND (115200 8N1)
set_property -dict { PACKAGE_PIN Y18 IOSTANDARD LVCMOS33 } [get_ports { uart_rx_pin }]
