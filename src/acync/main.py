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

import inspect
import random
from typing import Optional, TYPE_CHECKING, Dict, Union, Tuple, List

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


class CyncCloudAPI:
    API_TIMEOUT: int = 5

    def __init__(self, **kwargs):
        self.xlink_data: Optional[dict] = None

    def authenticate_2fa(self):
        """Authenticate with the API and get a token."""
        username = input("Enter Username/Email (or emailed OTP code):")
        if re.match("^\d+$", username):
            # if username is all digits, assume it's a OTP code
            code = str(username)
            username = input("Enter Username/Email:")
        else:
            # Ask to be sent an email with OTP code
            API_AUTH = "https://api.gelighting.com/v2/two_factor/email/verifycode"
            auth_data = {
                "corp_id": CORP_ID,
                "email": username,
                "local_lang": "en-us",
            }
            r = requests.post(API_AUTH, json=auth_data, timeout=self.API_TIMEOUT)
            code = input("Enter emailed OTP code:")

        password = getpass.getpass()
        API_AUTH = "https://api.gelighting.com/v2/user_auth/two_factor"
        auth_data = {
            "corp_id": CORP_ID,
            "email": username,
            "password": password,
            "two_factor": code,
            "resource": randomLoginResource(),
        }
        r = requests.post(API_AUTH, json=auth_data, timeout=self.API_TIMEOUT)

        try:
            return r.json()["access_token"], r.json()["user_id"]
        except KeyError:
            raise (xlinkException("API authentication failed"))

    def get_devices(self, auth_token: str, user: str):
        """Get a list of devices for a particular user."""
        API_DEVICES = "https://api.gelighting.com/v2/user/{user}/subscribe/devices"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            API_DEVICES.format(user=user), headers=headers, timeout=self.API_TIMEOUT
        )
        return r.json()

    def get_properties(self, auth_token: str, product_id: str, device_id: str):
        """Get properties for a single device."""
        API_DEVICE_INFO = "https://api.gelighting.com/v2/product/{product_id}/device/{device_id}/property"
        headers = {"Access-Token": auth_token}
        r = requests.get(
            API_DEVICE_INFO.format(product_id=product_id, device_id=device_id),
            headers=headers,
            timeout=self.API_TIMEOUT,
        )
        return r.json()


class ACync:

    def __init__(
        self, callback: Optional[Cync2MQTT.Cync2MQTT.callback_routine] = None, **kwargs
    ):
        self.networks: Dict[str, Network] = {}
        self.devices: Dict[str, CyncDevice] = {}
        self.mesh_map: Dict[str, Union[str, int, float]] = {}
        self.xlink_data: Optional[dict] = None
        self.cloud_api: CyncCloudAPI = CyncCloudAPI()
        self.callback: Optional[Cync2MQTT.Cync2MQTT.callback_routine] = callback

    # define our callback handler
    async def _callback_routine(self, device_status: Network.device_status):
        # get the file and line number of the caller
        caller = inspect.stack()[2]
        logger.debug(
            "ACync _callback_routine called by: %s:%d "
            "- data included in callback -> %s",
            Path(caller.filename).name,
            caller.lineno,
            device_status,
        )
        device: CyncDevice = self.devices[f"{device_status.name}/{device_status.id}"]
        device.online = True
        for attr in ("brightness", "red", "green", "blue", "color_temp"):
            setattr(device, attr, getattr(device_status, attr))
        if self.callback is not None:
            # Cync2MQTT callback_routine
            await self.callback(self, device_status)
        else:
            logger.debug(
                "ACync _callback_routine: no callback defined, ignoring"
            )

    def populate_from_configdict(self, configdict: dict):
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
                mesh_macs, mesh["mac"], str(mesh["access_key"]), bt_lib=usebtlib
            )

            async def cb(device_status: Network.device_status):
                return await self._callback_routine(device_status)

            # Set callback for mesh network
            logger.debug(
                "Setting callback for mesh network %s to %s", mesh["name"], cb
            )
            mesh_network.callback = cb
            # add mesh network to networks
            self.networks[mesh["name"]] = mesh_network

            # Create devices
            for cync_id, cync_device in mesh["bulbs"].items():
                device_type = cync_device["type"] if "type" in cync_device else None
                device_name = (
                    cync_device["name"]
                    if "name" in cync_device
                    else f"device_{cync_id}"
                )
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
            self.xlink_data = json.load(fp)
            logger.debug("loaded JSON file %s", jsonfile)
        for mesh in self.xlink_data:
            if "name" not in mesh or len(mesh["name"]) < 1:
                continue
            if "properties" not in mesh or "bulbsArray" not in mesh["properties"]:
                continue
            mesh_macs = []
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
                mesh_macs.append(mac)

            # print(f"Add network: {mesh['name']}")
            self.mesh_map[mesh["mac"]] = mesh["name"]
            usebtlib = None
            if "usebtlib" in mesh:
                usebtlib = mesh["usebtlib"]
            mesh_network = Network(
                mesh_macs, mesh["mac"], str(mesh["access_key"]), bt_lib=usebtlib
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
        logger.debug("ACync.disconnect(): Disconnecting from mesh network(s)")
        for device in self.devices.values():
            device.online = False

        for mesh in self.networks.values():
            await mesh.disconnect()
        logger.debug("ACync.disconnect(): Disconnected from mesh network(s)")

    async def connect(self) -> List[Optional[str]]:
        connected = list()
        mesh: Network
        try:
            for mesh_name, mesh in self.networks.items():
                if await mesh.connect():
                    connected.append(mesh_name)
        except Exception as e:
            await self.disconnect()
            logger.error(
                "acync: Unable to connect to mesh network(s) - %s", e, stacklevel=2
            )
            raise Exception("acync: Unable to connect to mesh network(s) - %s" % e)

        return connected

    # https://github.com/unixpickle/cbyge/blob/main/login.go

    def get_cloud_mesh_info(self):
        """Get Cync devices from the cloud, all cync devices are bt or bt/wifi.
        Meaning they will always have a BT mesh (as of March 2024)"""
        (auth, userid) = self.cloud_api.authenticate_2fa()
        mesh_networks = self.cloud_api.get_devices(auth, userid)
        for mesh in mesh_networks:
            mesh["properties"] = self.cloud_api.get_properties(
                auth, mesh["product_id"], mesh["id"]
            )
        return mesh_networks

    def mesh_to_config(self, mesh_info):
        mesh_config = {}

        for mesh in mesh_info:
            if "name" not in mesh or len(mesh["name"]) < 1:
                continue

            new_mesh = {
                kv: mesh[kv] for kv in ("access_key", "name", "mac") if kv in mesh
            }
            mesh_config[mesh["id"]] = new_mesh

            if "properties" not in mesh or "bulbsArray" not in mesh["properties"]:
                continue

            new_mesh["bulbs"] = {}
            for bulb in mesh["properties"]["bulbsArray"]:
                if any(
                    checkattr not in bulb
                    for checkattr in ("deviceID", "displayName", "mac", "deviceType")
                ):
                    continue
                # last 3 digits of deviceID
                __id = int(str(bulb["deviceID"])[-3:])
                bulb_device = CyncDevice(
                    None, bulb["displayName"], __id, bulb["mac"], bulb["deviceType"]
                )
                new_bulb = {}
                for attr_set in (
                    "name",
                    "is_plug",
                    "supports_temperature",
                    "supports_rgb",
                    "mac",
                ):
                    value = getattr(bulb_device, attr_set)
                    if value:
                        new_bulb[attr_set] = value
                new_mesh["bulbs"][__id] = new_bulb

        config_dict = {}
        # Set default values
        config_dict["mqtt_url"] = "mqtt://127.0.0.1:1883/"
        config_dict["meshconfig"] = mesh_config

        return config_dict
