# ESPHome running on a Waveshare esp32-s3-rs485-can

https://www.waveshare.com/esp32-s3-rs485-can.htm

You will need to connect the A+ to D+ and B- to D- (on Delta). Configure the baud rate (Modbus RTU) via the application in Advanced Configuration, Load management, external load management. 

Flash the Wavesahre with ESPHome (via website) and connect it to your wireless. 

Setup a configuration and try this (example is for a Delta AC Max Basic) : 


```yaml
esphome:
  name: "esphome-web-abcde"
  friendly_name: waveshare-modbus
  min_version: 2025.11.0
  name_add_mac_suffix: false

esp32:
  variant: esp32s3
  framework:
    type: esp-idf

# Enable logging
logger:

# Enable Home Assistant API # https://esphome.io/components/api/
api:
   encryption:
    key: ""
    
# Allow Over-The-Air updates
ota:
- platform: esphome

wifi:
  ssid: !secret wifi_ssid
  password: !secret wifi_password
  manual_ip:
    # Set this to the IP of the ESP
    static_ip: 192.168.xx.yy
    # Set this to the IP address of the router. Often ends with .1
    gateway: 192.168.xx.1
    # The subnet of the network. 255.255.255.0 works for most home networks.
    subnet: 255.255.255.0

uart:
- id: uart_modbus_client
  tx_pin: '17' #TX GPIO17 TX RS485
  rx_pin: '18' #RX GPIO18 RX RS485
  baud_rate: 19200 #115200
  stop_bits: 1
  data_bits: 8 #default to 8E1
  parity: NONE #default to 8E1
  

modbus:
  - uart_id: uart_modbus_client
    id: modbus_client
    send_wait_time: 200ms
    flow_control_pin: '21' # GPIO21 

modbus_controller:
- id: sdm
  address: 1
  modbus_id: modbus_client
  command_throttle: 100ms
  setup_priority: -10
  update_interval: 30s

sensor:
  - platform: modbus_controller
    modbus_controller_id: sdm
    name: "EVSE Charger State"
    address: 1000
    register_type: read
    value_type: U_WORD

text_sensor:
  - platform: modbus_controller
    modbus_controller_id: sdm
    name: "Charger Serial"
    address: 110
    register_type: read
    register_count: 10  # Number of 16-bit registers to read
    response_size: 20   # Total bytes to read
    #encoding: UTF-8    # Common encoding types: UTF-8, ASCII, etc.
    raw_encode: ANSI 
    # Optional transformations

```
