# cync2mqtt
Bridge Cync bluetooth mesh to mqtt. Includes auto-discovery for HomeAssistant.  Tested on Raspberry Pi3B+,Pi-Zero-W and [x86-64 linux docker](https://github.com/zimmra/cync2mqtt-docker)

## Features
- Supports home assistant [MQTT Discovery](https://www.home-assistant.io/docs/mqtt/discovery/)
- Supports mesh notifications (bulb status updates published to mqtt regardless of what set them).
- Cleanly recovers from communication errors both with the BLE mesh as well as MQTT broker.

## Requirements
- Linux like OS with bluez bluetooth stack.  Has been tested on a number of X86 and ARM (Raspberry Pi) configurations.  It might work on Windows but as far as I know no one has tried.
- MQTT broker (my config is mosquitto from [Entware](https://github.com/Entware/Entware) running on router). HASS Mosquitto broker also works.
- GE/Savant Cync Switches, Bulbs.
- Optional (but recommended): [Home Assistant](https://www.home-assistant.io/)

## Setup

### Docker
Running in a docker container is a good alternative to running the systemd virtual env setup.  Here are instructions for one possible way to setup using docker.

```shell
# Create a directory to store the mesh configuration file:
mkdir ~/docker/cync2mqtt

# Clone the repo and cd into it
git clone https://github.com/baudneo/cync2mqtt && cd cync2mqtt

# Build the image
docker compose build

# Run login and 2fa to get mesh configuration exported to a file:
docker run --rm -it -v ~/docker/cync2mqtt:/home/cync2mqtt cync2mqtt get_cync_config_from_cloud /home/cync2mqtt/cync_mesh.yaml

# Edit the generated yaml file as necessary.  The only thing which should be necessary at a minimum is to make sure the mqtt_url definition matches your MQTT broker.

# Edit the docker-compose.yaml file and set DEBUG: 1 for your first run
docker compose up
# If it connects to a mesh network, it is connected to one of the cync bt devices. Ctrl+C

# Run it in detached mode
docker compose up -d
# manage the service using docker compose <command> (docker compose logs -f, etc.)
```
### Non Docker
#### Create a python3 virtual env
```shell
python3 -mvenv ~/cync2mqtt/venv
```

#### install into virtual environment
```shell
~/cync2mqtt/venv/bin/pip3 install git+https://github.com/baudneo/cync2mqtt
```

##### Note Python3.10+
[AMQTT](https://github.com/Yakifo/amqtt) does not yet have a released version for Python3.10+.  To run with Python3.10+, you can currently install in virtual environment like this:
```shell
git clone https://github.com/baudneo/cync2mqtt.git src_cync2mqtt
~/cync2mqtt/venv/bin/pip3 install -r src_cync2mqtt/requirements.python3.10.txt  src_cync2mqtt/
```

#### Download Mesh Configuration from CYNC using 2FA
Make sure your devices are all configured in the Cync app, then:
```shell
~/cync2mqtt/venv/bin/get_cync_config_from_cloud ~/cync_mesh.yaml
```

You will be prompted for your username (email) - get a onetime passcode to that email you will enter - enter your cync account password.

### Edit generated configuration
Edit the generated yaml file as necessary.  The only thing which should be necessary at a minimum is to make sure the mqtt_url definition matches your MQTT broker.  Also see: [cync_mesh_example.yaml](cync_mesh_example.yaml) 

### Test Run
Run the script with the config file:
```shell
~/cync2mqtt/venv/bin/cync2mqtt  ~/cync_mesh.yaml
# debug logging
~/cync2mqtt/venv/bin/cync2mqtt  ~/cync_mesh.yaml --log-level debug
```

If it works you should see an INFO message similar to this:
```shell
cync2mqtt - INFO - Connected to mesh mac: XX:XX:XX:XX:XX:XX
```

You can view MQTT messages on the topics: acyncmqtt/# and homeassistant/# ...i.e:
```shell
mosquitto_sub -h $meship  -I rx -v -t 'acyncmqtt/#' -t 'homeassistant/#'
``` 


### Install systemd service (optional example for Raspberry PI OS)

```shell
sudo nano /etc/systemd/system/cync2mqtt.service
```
```ini 
[Unit]
Description=cync2mqtt
After=network.target

[Service]
ExecStart=/home/pi/venv/cync2mqtt/bin/cync2mqtt /home/pi/cync_mesh.yaml
Restart=always
User=pi

[Install]
WantedBy=multi-user.target
```

```shell
sudo systemctl enable cync2mqtt.service
```

## MQTT Topics
I recommend using a GUI like [mqqt-spy](https://github.com/eclipse/paho.mqtt-spy) to work with your MQTT broker.  Below are some basic mosquitto command line topic examples.  You need to also be subscribed with mosquitto command abvoe to see the responses.

Get list of devices - publish 'get' to topic acyncmqtt/devices, i.e: 
```shell
mosquitto_pub  -h $mqttip -t 'acyncmqtt/devices' -m get
```

You will receive a response on the topic ```homeassistant/devices/<meshid>/<deviceid>``` for every defined mesh and device.

Devices can be controlled by sending a message to the topic: ```acyncmqtt/set/<meshid>/<deviceid>```, i.e:

Turn on:
```shell
mosquitto_pub  -h $mqttip -I tx -t "acyncmqtt/set/$meshid/$deviceid" -m on
```

Turn off:
```shell
mosquitto_pub  -h $mqttip -I tx -t "acyncmqtt/set/$meshid/$deviceid" -m off
```

Set brightness:
```shell
mosquitto_pub  -h $mqttip -I tx -t "acyncmqtt/set/$meshid/$deviceid" -m '{"state": "on", "brightness" : 50}' 
```
## Issues
Certain direct connect devices (those with WIFI) have trouble connecting with the Linux Bluez-DBUS bluetooth-LE stack (can not connect/receive notiications).  If possible - the best workaround is to have at least one device in your mesh cync2mqtt can connect to that does not have these issues.  As a workaround, it is also possible to use [bluepy](https://github.com/IanHarvey/bluepy) which does not have these issues.  See the [cync_mesh_example.yaml](cync_mesh_example.yaml) for how to enable this.

## Notes
Outside of the initial setup of downloading the mesh credentials from your cloud account, this has no dependencies on the cloud.  If neccessary, in the future a standalone pairing script can also be written to remove all cloud depdendencies.  Generally though for my own setup - I find having the cloud connectivity good to have for Alexa/Google Home support and then having HomeAssistant support via this mqtt bridge to bluetooth.  Several other alternatives also exist out there depending on what your own needs may be:
- [cync_lights](https://github.com/nikshriv/cync_lights/tree/main) - Home assistant custom component that does all communication with the cloud server.
- [cbyge](https://github.com/unixpickle/cbyge/tree/main) - Standalone app to communicate with the cloud server.  I believe this also has a mqtt wrapper interface which has been developed.
- [cync-lan](https://github.com/iburistu/cync-lan) - A good proof of concept of direct wifi connection to cync devices.  This almost makes me want to block the official cloud access to my Cync devices :-).

## Acknowledgments
- Telink-Mesh python: https://github.com/google/python-laurel
- 2FA Cync login: https://github.com/unixpickle/cbyge/blob/main/login.go
- Async BLE python: https://pypi.org/project/bleak/
- Async MQTT: https://amqtt.readthedocs.io/en/latest/index.html
- [zimmra](https://github.com/zimmra) for docker container, debug, and testing.



```log
# Plug (id: 4) toggled in Cync App - Plug has weird issue where it shows offline in HASS. Plug is connected to via bluetooth from phone or WiFi.
mesh:169 -> btle gatt: bluepy: handleNotification: adding to notification queue with id: 114
mesh:222 -> btle_gatt:bluepy: notify_worker: got item from notify_queue => noti_id: 114 // data: b'7\x00\x00\x06\x00\xe1/\xa98\x92\xa9\x99\xdamT\xd4\xb6\x06g\x07'
mesh:797 -> bt noti:id:114: Full Decrypted data: [55, 0, 0, 6, 0, 225, 47, 234, 17, 2, 6, 161, 1, 1, 1, 0, 0, 0, 0, 0]
mesh:819 -> bt noti:id:114: [6, 161, 1, 1] => device_id: 6 // brightness: 1 // UNKNOWN: 161
mesh:838 -> bt noti:id:114: Tunable white data (or plug)! [6, 161, 1, 1] => device_id: 6 // brightness: 1 // UNKNOWN: 161 // color_temp = 1
mesh:843 -> bt noti:id:114: Unknown command [byte 8]: 0xea/234 (Expected 0xdc/220), not sending back down the callback stack!
mesh:865 -> bt noti:id:114: Only 1/2 responses processed => [6, 161, 1, 1, 1, 0, 0, 0]


mesh:169 -> btle gatt: bluepy: handleNotification: adding to notification queue with id: 52
mesh:222 -> btle_gatt:bluepy: notify_worker: got item from notify_queue => noti_id: 52 // data: b'9\x00\x00\x06\x00\x8b\xf2QR\x0c\x89\x8dls-.>\xae3\xb1'
mesh:797 -> bt noti:id=52: Full Decrypted data: [57, 0, 0, 6, 0, 139, 242, 234, 17, 2, 6, 161, 1, 1, 1, 0, 0, 0, 0, 0]
mesh:819 -> bt noti:id=52: [6, 161, 1, 1] => device_id: 6 // brightness: 1 // UNKNOWN: 161
mesh:838 -> bt noti:id=52: Tunable white data (or plug)! [6, 161, 1, 1] => device_id: 6 // brightness: 1 // UNKNOWN: 161 // color_temp = 1
mesh:843 -> bt noti:id=52: Unknown command [byte 8]: 0xea/234 (Expected 0xdc/220), not sending back down the callback stack!
mesh:865 -> bt noti:id=52: Only 1/2 responses processed => [6, 161, 1, 1, 1, 0, 0, 0]



cync2mqtt Cync2MQTT:281 -> sub_worker - acyncmqtt/set/7B19400144A4D0F4/1 => bytearray(b'{"state":"ON","brightness":41}')
acync.mesh mesh:169 -> btle gatt: bluepy: handleNotification: adding to notification queue with id: 117
acync.mesh mesh:222 -> btle_gatt:bluepy: notify_worker: got item from notify_queue => noti_id: 117 // data: b'\xdd8\x00\x00\x00\x83:LX\xdd\x895i\xad\xd4\x12\x16L\xaf0'
acync.mesh mesh:797 -> bt noti:id=117: Full Decrypted data: [221, 56, 0, 0, 0, 131, 58, 220, 17, 2, 1, 1, 41, 12, 0, 0, 0, 0, 0, 0]
acync.mesh mesh:819 -> bt noti:id=117: [1, 1, 41, 12] => device_id: 1 // brightness: 41 // UNKNOWN: 1
acync.mesh mesh:838 -> bt noti:id=117: Tunable white data (or plug)! [1, 1, 41, 12] => device_id: 1 // brightness: 41 // UNKNOWN: 1 // color_temp = 12
acync main:132 -> ACync _callback_routine called by: mesh.py:848 - data included in callback -> DeviceStatus(name='7B19400144A4D0F4', id=1, brightness=41, rgb=False, red=0, green=0, blue=0, color_temp=12, notification_id=117)
acync.mesh mesh:865 -> bt noti:id=117: Only 1/2 responses processed => [1, 1, 41, 12, 0, 0, 0, 0]
```