# CYNC / C-GE bluetooth mesh light control implemented with BLEAK: https://github.com/hbldh/bleak

# lots of information from
# https://github.com/google/python-laurel
# http://wiki.telink-semi.cn/tools_and_sdk/BLE_Mesh/SIG_Mesh/sig_mesh_sdk.zip

# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Contains code derived from python-tikteck,
# Copyright 2016 Matthew Garrett <mjg59@srcf.ucam.org>
from __future__ import annotations

import random
from typing import Optional, TYPE_CHECKING, Dict, Union, Tuple

import requests
import getpass
import json
from pathlib import Path
from .mesh import Network, CyncDevice
import logging
import re

if TYPE_CHECKING:
    import Cync2MQTT

__all__ = ["ACync", "xlinkException", "LOG_NAME", "randomLoginResource"]
LOG_NAME = "acync"
logger = logging.getLogger(LOG_NAME)
logger.addHandler(logging.NullHandler())
CORP_ID: str = "1007d2ad150c4000"

class xlinkException(Exception):
    pass


def randomLoginResource():
    return "".join([chr(ord("a") + random.randint(0, 26)) for i in range(0, 16)])


class ACync:
    API_TIMEOUT = 5
    LOG_NAME = LOG_NAME

    # https://github.com/unixpickle/cbyge/blob/main/login.go
    @staticmethod
    def _authenticate_2fa():
        """Authenticate with the API and get a token."""
        username = input("Enter Username (or emailed code):")
        if re.match("^\d+$", username):
            code = str(username)
            username = input("Enter Username:")
        else:
            API_AUTH = "https://api.gelighting.com/v2/two_factor/email/verifycode"
            auth_data = {
                "corp_id": CORP_ID,
                "email": username,
                "local_lang": "en-us",
            }
            r = requests.post(API_AUTH, json=auth_data, timeout=ACync.API_TIMEOUT)
            code = input("Enter emailed code:")

        password = getpass.getpass()
        API_AUTH = "https://api.gelighting.com/v2/user_auth/two_factor"
        auth_data = {
            "corp_id": CORP_ID,
            "email": username,
            "password": password,
            "two_factor": code,
            "resource": randomLoginResource(),
        }
        r = requests.post(API_AUTH, json=auth_data, timeout=ACync.API_TIMEOUT)

        try:
            return r.json()["access_token"], r.json()["user_id"]
        except KeyError:
            raise (xlinkException("API authentication failed"))

    def _get_devices(auth_token: str, user: str):
        """Get a list of devices for a particular user."""
        API_DEVICES = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            API_DEVICES.format(user=user), headers=headers, timeout=ACync.API_TIMEOUT
        )
        return r.json()

    def _get_properties(auth_token: str, product_id: str, device_id: str):
        """Get properties for a single device."""
        API_DEVICE_INFO = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            API_DEVICE_INFO.format(product_id=product_id, device_id=device_id),
            headers=headers,
            timeout=ACync.API_TIMEOUT,
        )
        return r.json()

    @staticmethod
    def get_app_meshinfo():
        (auth, userid) = ACync._authenticate_2fa()
        mesh_networks = ACync._get_devices(auth, userid)
        for mesh in mesh_networks:
            mesh["properties"] = ACync._get_properties(
                auth, mesh["product_id"], mesh["id"]
            )
        return mesh_networks

    def app_meshinfo_to_configdict(self, meshinfo):
        meshconfig = {}

        for mesh in meshinfo:
            if "name" not in mesh or len(mesh["name"]) < 1:
                continue
            newmesh = {
                kv: mesh[kv] for kv in ("access_key", "name", "mac") if kv in mesh
            }
            meshconfig[mesh["id"]] = newmesh

            if "properties" not in mesh or "bulbsArray" not in mesh["properties"]:
                continue

            newmesh["bulbs"] = {}
            for bulb in mesh["properties"]["bulbsArray"]:
                if any(
                    checkattr not in bulb
                    for checkattr in ("deviceID", "displayName", "mac", "deviceType")
                ):
                    continue
                id = int(str(bulb["deviceID"])[-3:])
                bulbdevice = CyncDevice(
                    None, bulb["displayName"], id, bulb["mac"], bulb["deviceType"]
                )
                newbulb = {}
                for attrset in (
                    "name",
                    "is_plug",
                    "supports_temperature",
                    "supports_rgb",
                    "mac",
                ):
                    value = getattr(bulbdevice, attrset)
                    if value:
                        newbulb[attrset] = value
                newmesh["bulbs"][id] = newbulb

        configdict = {}
        configdict["mqtt_url"] = "mqtt://127.0.0.1:1883/"
        configdict["meshconfig"] = meshconfig

        return configdict

    def __init__(
        self, callback: Optional[Cync2MQTT.Cync2MQTT.callback_routine] = None, **kwargs
    ):
        from .Cync2MQTT import Cync2MQTT

        self.networks: Dict[str, Network] = {}
        self.devices: Dict[str, CyncDevice] = {}
        self.mesh_map: Dict[str, Union[str, int, float]] = {}
        self.xlinkdata: Optional[dict] = None
        self.callback: Optional[Cync2MQTT.callback_routine] = callback

    # define our callback handler
    async def _callback_routine(self, device_status: Network.device_status):
        device: CyncDevice = self.devices[f"{device_status.name}/{device_status.id}"]
        device.online = True
        for attr in ("brightness", "red", "green", "blue", "color_temp"):
            setattr(device, attr, getattr(device_status, attr))
        if self.callback is not None:
            await self.callback(self, device_status)

    def populate_from_configdict(self, configdict):
        logger.debug(
            "%s: attempting to create bt mesh from YAML config file...", LOG_NAME
        )
        for mesh_id, mesh in configdict["meshconfig"].items():
            if "name" not in mesh:
                mesh["name"] = f"mesh_{mesh_id}"
            # this sets device priority to 0 if not in config
            mesh_macs: Dict[str, Tuple[int, str, int]] = {}
            for cync_id, cync_device in mesh["bulbs"].items():
                # support MAC in config with either colons or not
                mac = cync_device["mac"].replace(":", "")
                mac = ":".join(mac[i : i + 2] for i in range(0, 12, 2))
                priority = cync_device["priority"] if "priority" in cync_device else 0
                timeout = cync_device["timeout"] if "timeout" in cync_device else 30
                mesh_macs[mac] = (priority, cync_device["name"], timeout)

            # add MAC to meshmap
            self.mesh_map[mesh["mac"]] = mesh["name"]

            usebtlib = None
            if "usebtlib" in mesh:
                usebtlib = mesh["usebtlib"]

            # Create the mesh network
            mesh_network = Network(
                mesh_macs, mesh["mac"], str(mesh["access_key"]), usebtlib=usebtlib
            )

            async def cb(device_status: Network.device_status):
                return await self._callback_routine(device_status)
            # Set callback for mesh network
            mesh_network.callback = cb
            # add mesh network to networks
            self.networks[mesh["name"]] = mesh_network

            # Create devices
            for cync_id, cync_device in mesh["bulbs"].items():
                device_type = cync_device["type"] if "type" in cync_device else None
                device_name = cync_device["name"] if "name" in cync_device else f"device_{cync_id}"
                new_device = CyncDevice(
                    mesh_network, device_name, cync_id, cync_device["mac"], device_type
                )
                for attrset in ("is_plug", "supports_temperature", "supports_rgb"):
                    if attrset in cync_device:
                        setattr(new_device, attrset, cync_device[attrset])
                self.devices[f"{mesh['mac']}/{cync_id}"] = new_device

    def populate_from_jsonfile(self, jsonfile):
        jsonfile = Path(jsonfile)

        with jsonfile.open("rt") as fp:
            self.xlinkdata = json.load(fp)
            logger.debug("loaded JSON file %s", jsonfile)
        for mesh in self.xlinkdata:
            if "name" not in mesh or len(mesh["name"]) < 1:
                continue
            if "properties" not in mesh or "bulbsArray" not in mesh["properties"]:
                continue
            meshmacs = []
            for bulb in mesh["properties"]["bulbsArray"]:
                mac = [bulb["mac"][i : i + 2] for i in range(0, 12, 2)]
                mac = "%s:%s:%s:%s:%s:%s" % (
                    mac[0],
                    mac[1],
                    mac[2],
                    mac[3],
                    mac[4],
                    mac[5],
                )
                meshmacs.append(mac)

            # print(f"Add network: {mesh['name']}")
            self.mesh_map[mesh["mac"]] = mesh["name"]
            usebtlib = None
            if "usebtlib" in mesh:
                usebtlib = mesh["usebtlib"]
            mesh_network = Network(
                meshmacs, mesh["mac"], str(mesh["access_key"]), usebtlib=usebtlib
            )

            async def cb(devicestatus):
                return await self._callback_routine(devicestatus)

            mesh_network.callback = cb

            self.networks[mesh["name"]] = mesh_network

            for bulb in mesh["properties"]["bulbsArray"]:
                id = int(bulb["deviceID"][-3:])
                self.devices[f"{mesh['mac']}/{id}"] = CyncDevice(
                    mesh_network,
                    bulb["displayName"],
                    id,
                    bulb["mac"],
                    bulb["deviceType"],
                )

    async def disconnect(self):
        for device in self.devices.values():
            device.online = False

        for mesh in self.networks.values():
            await mesh.disconnect()

    async def connect(self):
        connected = list()
        mesh: Network
        try:
            for mesh_name, mesh in self.networks.items():
                if await mesh.connect():
                    connected.append(mesh_name)
        except Exception as e:
            await self.disconnect()
            logger.error("acync: Unable to connect to mesh network(s) - %s", e, stacklevel=2)
            raise Exception("acync: Unable to connect to mesh network(s) - %s" % e)

        return connected
