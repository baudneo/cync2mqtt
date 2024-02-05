# CYNC / C-GE bluetooth mesh light control implemented with BLEAK: https://github.com/hbldh/bleak
import asyncio
import concurrent.futures
import functools
import logging
import queue
import random
from collections import namedtuple
from typing import Optional, Union, Dict, Tuple

import bluepy.btle
from Crypto.Cipher import AES
import Crypto.Random
from bleak import BleakClient, BleakScanner, BLEDevice, AdvertisementData

# some information from:
# http://wiki.telink-semi.cn//tools_and_sdk/BLE_Mesh/Telink_Mesh/telink_mesh_sdk.zip
# implementation largely based on:
# https://github.com/google/python-dimond
# and
# https://github.com/google/python-laurel
# which are...
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

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())
SCAN_TIMEOUT = 3


def encrypt(key, data):
    k = AES.new(bytes(reversed(key)), AES.MODE_ECB)
    data = reversed(list(k.encrypt(bytes(reversed(data)))))
    rev = []
    for d in data:
        rev.append(d)
    return rev


def generate_sk(name, password, data1, data2):
    name = name.ljust(16, chr(0))
    password = password.ljust(16, chr(0))
    key = [ord(a) ^ ord(b) for a, b in zip(name, password)]
    data = data1[0:8]
    data += data2[0:8]
    return encrypt(key, data)


def key_encrypt(name, password, key):
    name = name.ljust(16, chr(0))
    password = password.ljust(16, chr(0))
    data = [ord(a) ^ ord(b) for a, b in zip(name, password)]
    return encrypt(key, data)


def encrypt_packet(sk, address, packet):
    auth_nonce = [
        address[0],
        address[1],
        address[2],
        address[3],
        0x01,
        packet[0],
        packet[1],
        packet[2],
        15,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]

    authenticator = encrypt(sk, auth_nonce)

    for i in range(15):
        authenticator[i] = authenticator[i] ^ packet[i + 5]

    mac = encrypt(sk, authenticator)

    for i in range(2):
        packet[i + 3] = mac[i]

    iv = [
        0,
        address[0],
        address[1],
        address[2],
        address[3],
        0x01,
        packet[0],
        packet[1],
        packet[2],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]

    temp_buffer = encrypt(sk, iv)
    for i in range(15):
        packet[i + 5] ^= temp_buffer[i]

    return packet


def decrypt_packet(sk, address, packet):
    iv = [
        address[0],
        address[1],
        address[2],
        packet[0],
        packet[1],
        packet[2],
        packet[3],
        packet[4],
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]
    plaintext = [0] + iv[0:15]

    result = encrypt(sk, plaintext)

    for i in range(len(packet) - 7):
        packet[i + 7] ^= result[i]

    return packet


class BluePyDelegate(bluepy.btle.DefaultDelegate):
    def __init__(self, notifyqueue):
        bluepy.btle.DefaultDelegate.__init__(self)
        self.notifyqueue = notifyqueue

    def handleNotification(self, cHandle, data):
        self.notifyqueue.put((cHandle, data))


class BtLEGATT(object):
    def __init__(self, mac: str, uselib: str = "bleak", friendly_name: Optional[str] = None):
        self.mac_rssi: Optional[int] = None
        self.mac: str = mac
        self.is_connected: Optional[bool] = None
        self.notifytasks = None
        self.notifyqueue = None
        self._notifycallbacks: dict = {}
        self.loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
        self.bluepy_lock: asyncio.Lock = asyncio.Lock()
        self.macdata = None
        self.sk = None
        self._uuidchars: dict = {}
        self.client: Union[BleakClient, bluepy.btle.Peripheral, None]
        self.use_bt_lib: Optional[str] = uselib
        self.discovered_devices: Optional[Dict[str, Tuple[BLEDevice, AdvertisementData]]] = {}
        self.friendly_name: Optional[str] = friendly_name

        if uselib == "bleak":
            self.client = None

        elif uselib == "bluepy":
            logger.info("btle_gatt: using bluepy library")
            self.client = bluepy.btle.Peripheral()
        else:
            raise ValueError("btle_gatt: bluetooth library: %s not supported" % uselib)

    async def notify_worker(self):
        pool = concurrent.futures.ThreadPoolExecutor(1)
        while True:
            (handle, data) = await self.loop.run_in_executor(pool, self.notifyqueue.get)
            if handle in self._notifycallbacks:
                await self._notifycallbacks[handle](handle, data)

            await self.loop.run_in_executor(pool, self.notifyqueue.task_done)

    async def notify_waiter(self):
        pool = concurrent.futures.ThreadPoolExecutor(1)
        while True:
            await asyncio.sleep(0.25)
            async with self.bluepy_lock:
                await self.loop.run_in_executor(
                    pool, self.client.waitForNotifications, 0.25
                )

    async def discover(self):
        self.discovered_devices = await BleakScanner.discover(timeout=SCAN_TIMEOUT, return_adv=True)
        if not self.discovered_devices:
            logger.debug(f"btle_gatt: no devices discovered!")
        else:
            logger.debug(f"btle_gatt: discovered {len(self.discovered_devices)} devices")
        return self.discovered_devices

    async def connect(self, timeout=20):
        # logger.debug(f"btle_gatt: connect called for device: {self.mac} [{self.friendly_name}]")
        if self.is_connected:
            logger.debug(f"btle_gatt: already connected to {self.mac}")
            return
        self.macdata = None
        self.sk = None
        self._uuidchars = {}

        if isinstance(self.client, bluepy.btle.Peripheral):
            async with self.bluepy_lock:
                result = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1),
                    functools.partial(
                        self.client.connect,
                        self.mac,
                        addrType=bluepy.btle.ADDR_TYPE_PUBLIC,
                    ),
                )
                self.notifyqueue = queue.Queue()
                self.notifytasks = []
                self.notifytasks.append(asyncio.create_task(self.notify_worker()))
                self.client.setDelegate(BluePyDelegate(self.notifyqueue))
                status = self.client.status()
                result = status.get("state") == ['conn']
                logger.debug(f"btle_gatt:{self.use_bt_lib}: status() = {status} -- {result = }")
                self.is_connected = result

            return result
        else:
            # bleak
            device = None
            if self.mac not in self.discovered_devices:
                await self.discover()
            if self.mac in self.discovered_devices:
                device = self.discovered_devices[self.mac][0]
                advertisement = self.discovered_devices[self.mac][1]
                self.mac_rssi = advertisement.rssi
                logger.debug(f"btle_gatt:{self.use_bt_lib}: Scanning found device: {self.friendly_name} - "
                             f" Device: {device} --- Advertisement: {advertisement}")
            if device is None:
                logger.error(
                    f"btle_gatt:{self.use_bt_lib}: Scanning could not find device: {self.mac} [{self.friendly_name}]"
                )
                return

            self.client = BleakClient(device)
            status = await self.client.connect(timeout=timeout)
            self.is_connected = status
            return status

    async def bluepy_get_char_from_uuid(self, uuid):
        if uuid in self._uuidchars:
            return self._uuidchars[uuid]
        else:
            async with self.bluepy_lock:
                char = (
                    await self.loop.run_in_executor(
                        concurrent.futures.ThreadPoolExecutor(1),
                        functools.partial(self.client.getCharacteristics, uuid=uuid),
                    )
                )[0]
                self._uuidchars[uuid] = char
            return char

    async def write_gatt_char(self, uuid, data, withResponse=False):
        if isinstance(self.client, bluepy.btle.Peripheral):
            char = await self.bluepy_get_char_from_uuid(uuid)
            async with self.bluepy_lock:
                result = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1),
                    functools.partial(char.write, data, withResponse=withResponse),
                )
            return result
        elif isinstance(self.client, BleakClient):
            return await self.client.write_gatt_char(uuid, data, withResponse)

    async def read_gatt_char(self, uuid):
        if isinstance(self.client, bluepy.btle.Peripheral):
            char = await self.bluepy_get_char_from_uuid(uuid)
            async with self.bluepy_lock:
                result = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1), char.read
                )
            return result
        elif isinstance(self.client, BleakClient):
            return await self.client.read_gatt_char(uuid)

    async def disconnect(self):
        if self.notifytasks is not None:
            for notifytask in self.notifytasks:
                notifytask.cancel()

        if isinstance(self.client, bluepy.btle.Peripheral):
            async with self.bluepy_lock:
                result = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1), self.client.disconnect
                )
            return result
        else:
            return await self.client.disconnect()

    async def start_notify(self, uuid, callback_handler):
        if isinstance(self.client, bluepy.btle.Peripheral):
            char = await self.bluepy_get_char_from_uuid(uuid)
            async with self.bluepy_lock:
                handle = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1), char.getHandle
                )
            self._notifycallbacks[handle] = callback_handler
            self.notifytasks.append(asyncio.create_task(self.notify_waiter()))
        elif isinstance(self.client, BleakClient):
            return await self.client.start_notify(uuid, callback_handler)


class ATELinkMesh:
    # http://wiki.telink-semi.cn/wiki/protocols/Telink-Mesh/

    notification_char = "00010203-0405-0607-0809-0a0b0c0d1911"
    control_char = "00010203-0405-0607-0809-0a0b0c0d1912"
    pairing_char = "00010203-0405-0607-0809-0a0b0c0d1914"

    def __init__(
            self,
            vendor,
            mesh_macs: Dict[str, Tuple[int, str, int]],
            name: str,
            password: str,
            usebtlib: Optional[str] = None,
    ):
        self.vendor = vendor
        self.mesh_macs = (
            {x: (0, 'unknown') for x in mesh_macs} if type(mesh_macs) is list else mesh_macs
        )
        self.name: str = name
        self.password: str = password
        self.packet_count = random.randrange(0xFFFF)
        self.mac_data = None
        self.sk = None
        self.client = None
        self.current_mac: Optional[str] = ""
        if usebtlib is None:
            self.use_bt_lib = "bleak"
        else:
            self.use_bt_lib = usebtlib

    async def __aenter__(self):
        logger.debug("telink mesh: __aenter__")
        await self.connect()
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        logger.debug("telink mesh: __aexit__")
        await self.disconnect()

    async def disconnect(self):
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception as e:
                logger.info("disconnect returned false -> %s" % e)
            self.client = None

    async def callback_handler(self, sender, data):
        print(
            "{0}: {1}".format(
                sender, decrypt_packet(self.sk, self.mac_data, list(data))
            )
        )

    async def connect(self):
        self.mac_data = None
        self.sk = None
        total_macs = len(self.mesh_macs)

        for retry in range(0, 3):
            if self.sk is not None:
                # Assuming we are already connected
                break
            # self.meshmacs schema -> { MAC[str] : (priority[int], firendly_name[str]) }
            for mac_idx, mac in enumerate(
                    sorted(self.mesh_macs, key=lambda x: self.mesh_macs[x][0])
            ):
                mac_priority = self.mesh_macs[mac][0]
                mac_friendly_name = self.mesh_macs[mac][1]
                logger.debug(
                    f"telink mesh:connect: attempt: {retry + 1}/3 to MAC ({mac_idx + 1}/{total_macs}): {mac} "
                    f"[{mac_friendly_name}] Timeout: {SCAN_TIMEOUT}"
                )
                # if priority is less than 0, skip it
                if mac_priority < 0:
                    logger.warning(
                        f"telink mesh:connect: Skipping, priority < 0 -> MAC: {mac} [{mac_friendly_name}]"
                    )
                    continue
                self.client = BtLEGATT(mac, uselib=self.use_bt_lib, friendly_name=mac_friendly_name)

                try:
                    # BtLEGATT.connect wrapper
                    await self.client.connect()
                except Exception as e:
                    # increment priority
                    mac_priority += 1
                    self.mesh_macs[mac] = (mac_priority, mac_friendly_name)
                    exc_ = True if not str(e) else False
                    logger.info(
                        "telink mesh:connect: EXCEPTION! Unable to CONNECT to device: %s [%s] --> %s"
                        % (mac, mac_friendly_name, e),
                        exc_info=exc_,
                    )
                    await asyncio.sleep(0.1)
                    continue
                if not self.client.is_connected:
                    # logger.info(
                    #     "telink mesh: NOT CONNECTED! Initial connection worked but now unable "
                    #     "to connect to mesh mac: %s" % mac
                    # )
                    continue

                self.current_mac = mac
                mac_array = mac.split(":")
                self.mac_data = [
                    int(mac_array[5], 16),
                    int(mac_array[4], 16),
                    int(mac_array[3], 16),
                    int(mac_array[2], 16),
                    int(mac_array[1], 16),
                    int(mac_array[0], 16),
                ]
                # create random 8 byte challenge for pairing and secure key generation
                data = [0] * 16
                random_data = Crypto.Random.get_random_bytes(8)
                for i in range(8):
                    data[i] = random_data[i]

                enc_data = key_encrypt(self.name, self.password, data)
                packet = [0x0C]
                packet += data[0:8]
                packet += enc_data[0:8]

                try:
                    await self.client.write_gatt_char(
                        ATELinkMesh.pairing_char, bytes(packet), True
                    )
                    await asyncio.sleep(0.3)
                    data2 = await self.client.read_gatt_char(ATELinkMesh.pairing_char)
                except Exception as e:
                    logger.warning(
                        "telink mesh:connect: Exception! Unable to PAIR to mesh mac: %s -> %s"
                        % (mac, e),
                        exc_info=True,
                    )
                    await self.client.disconnect()
                    self.sk = None
                    continue
                else:
                    # logger.debug(
                    #     f"telink mesh:connect: Paired to device: {mac} [{mac_friendly_name}]"
                    # )
                    self.sk = generate_sk(
                        self.name, self.password, data[0:8], data2[1:9]
                    )

                    try:
                        await self.client.start_notify(
                            ATELinkMesh.notification_char, self.callback_handler
                        )
                        await asyncio.sleep(0.3)
                        await self.client.write_gatt_char(
                            ATELinkMesh.notification_char, bytes([0x1]), True
                        )
                        await asyncio.sleep(0.3)
                        _ = await self.client.read_gatt_char(
                            ATELinkMesh.notification_char
                        )
                    except Exception as e:
                        logger.info(
                            f"telink mesh:connect: Unable to connect to mesh mac for notify: %s -> %s"
                            % (mac, e),
                        )
                        await self.client.disconnect()
                        self.sk = None
                        continue
                    else:
                        logger.info(f"telink mesh:connect: Connected to mesh ID: {self.name} via MAC: {mac} [{mac_friendly_name}]")

                    break

        return self.sk is not None

    async def update_status(self):
        if self.sk is None:
            logger.info(f"telink mesh:update_status: Attempt re-connect...")
            if not self.connect():
                return False
        
        # logger.debug(f"telink mesh:update_status: current_mac: {self.current_mac}")

        ok = False
        for trycount in range(0, 3):
            if ok:
                break
            try:
                await self.client.write_gatt_char(
                    ATELinkMesh.notification_char, bytes([0x1]), True
                )
                await asyncio.sleep(0.3)
                _ = await self.client.read_gatt_char(ATELinkMesh.notification_char)
                ok = True
            except Exception as e:
                logger.info(
                    "update_status - Unable to send to mesh, retry... -> %s"
                    % e,
                )
                try2 = 0
                connected = False
                while not connected and try2 < 3:
                    self.mesh_macs[self.current_mac][0] += 1
                    self.current_mac = ""
                    await asyncio.sleep(0.1)
                    logger.info("Disconnect...")
                    await self.disconnect()
                    await asyncio.sleep(0.1)
                    logger.info("Disconnected... reconnecting...")
                    connected = await self.connect()
                    try2 += 1
                if not connected:
                    return False
        return ok

    @property
    def online(self):
        return (
                self.client is not None
                and self.sk is not None
                and self.mac_data is not None
        )

    async def send_packet(self, target, command, data):
        if not self.online:
            logger.debug(f"telink mesh:send_packet: Not online! - Attempt re-connect...")
            if not await self.connect():
                return False

        # logger.debug(f"telink mesh:send_packet: current_mac: {self.current_mac}")
        packet = [0] * 20
        packet[0] = self.packet_count & 0xFF
        packet[1] = self.packet_count >> 8 & 0xFF
        packet[5] = target & 0xFF
        packet[6] = (target >> 8) & 0xFF
        packet[7] = command
        packet[8] = self.vendor & 0xFF
        packet[9] = (self.vendor >> 8) & 0xFF
        for i in range(len(data)):
            packet[10 + i] = data[i]
        enc_packet = encrypt_packet(self.sk, self.mac_data, packet)
        self.packet_count += 1
        if self.packet_count > 65535:
            self.packet_count = 1

        for trycount in range(0, 3):
            try:
                await self.client.write_gatt_char(
                    Network.control_char, bytes(enc_packet)
                )
            except Exception as e:
                logger.info(
                    f"send_packet - Unable to connect for sending to mesh -> %s" % e
                )
                if trycount < 2:
                    self.mesh_macs[self.current_mac] += 1
                    self.current_mac = ""
                    await asyncio.sleep(0.1)
                    await self.disconnect()
                    await asyncio.sleep(0.1)
                    await self.connect()
                else:
                    return False
            break
        return True


class Network(ATELinkMesh):
    device_status = namedtuple(
        "DeviceStatus",
        ["name", "id", "brightness", "rgb", "red", "green", "blue", "color_temp"],
    )

    def __init__(
            self,
            mesh_macs: Dict[str, Tuple[int, str, int]],
            name: str,
            password: str,
            usebtlib: Optional[str] = None,
            **kwargs,
    ):
        self.callback = kwargs.get("callback", None)
        super().__init__(0x0211, mesh_macs, name, password, usebtlib)

    async def callback_handler(self, sender, data):
        if self.callback is None:
            return
        data = list(data)
        if len(data) < 19:
            return
        data = decrypt_packet(self.sk, self.mac_data, data)
        if data[7] != 0xDC:
            return

        responses = data[10:18]
        for i in (0, 4):
            response = responses[i: i + 4]
            if response[1] == 0:
                continue
            _id = response[0]
            brightness = response[2]
            (red, green, blue) = (0, 0, 0)
            color_temp = 0
            if brightness >= 128:
                # It supports RGB
                brightness = brightness - 128
                red = int(((response[3] & 0xE0) >> 5) * 255 / 7)
                green = int(((response[3] & 0x1C) >> 2) * 255 / 7)
                blue = int((response[3] & 0x3) * 255 / 3)
                rgb = True
            else:
                # It only supports white
                color_temp = response[3]
                rgb = False
            await self.callback(
                Network.device_status(
                    self.name, _id, brightness, rgb, red, green, blue, color_temp
                )
            )


class CyncDevice:
    # from: https://github.com/nikshriv/cync_lights/blob/main/custom_components/cync_lights/cync_hub.py
    Capabilities = {
        "ONOFF": [
            1,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            13,
            14,
            15,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
            35,
            36,
            37,
            38,
            39,
            40,
            48,
            49,
            51,
            52,
            53,
            54,
            55,
            56,
            57,
            58,
            59,
            61,
            62,
            63,
            64,
            65,
            66,
            67,
            68,
            80,
            81,
            82,
            83,
            85,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            148,
            149,
            150,
            151,
            152,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "BRIGHTNESS": [
            1,
            5,
            6,
            7,
            8,
            9,
            10,
            11,
            13,
            14,
            15,
            17,
            18,
            19,
            20,
            21,
            22,
            23,
            24,
            25,
            26,
            27,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
            35,
            36,
            37,
            48,
            49,
            55,
            56,
            80,
            81,
            82,
            83,
            85,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            148,
            149,
            150,
            151,
            152,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "COLORTEMP": [
            5,
            6,
            7,
            8,
            10,
            11,
            14,
            15,
            19,
            20,
            21,
            22,
            23,
            25,
            26,
            28,
            29,
            30,
            31,
            32,
            33,
            34,
            35,
            80,
            82,
            83,
            85,
            129,
            130,
            131,
            132,
            133,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "RGB": [
            6,
            7,
            8,
            21,
            22,
            23,
            30,
            31,
            32,
            33,
            34,
            35,
            131,
            132,
            133,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            146,
            147,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "MOTION": [37, 49, 54],
        "AMBIENT_LIGHT": [37, 49, 54],
        "WIFICONTROL": [
            36,
            37,
            38,
            39,
            40,
            48,
            49,
            51,
            52,
            53,
            54,
            55,
            56,
            57,
            58,
            59,
            61,
            62,
            63,
            64,
            65,
            66,
            67,
            68,
            80,
            81,
            128,
            129,
            130,
            131,
            132,
            133,
            134,
            135,
            136,
            137,
            138,
            139,
            140,
            141,
            142,
            143,
            144,
            145,
            146,
            147,
            148,
            149,
            150,
            151,
            152,
            153,
            154,
            156,
            158,
            159,
            160,
            161,
            162,
            163,
            164,
            165,
        ],
        "PLUG": [64, 65, 66, 67, 68],
        "FAN": [81],
        "MULTIELEMENT": {"67": 2},
    }

    def __init__(self, mesh_network, name, _id, mac, _type=None):
        self.network: ATELinkMesh = mesh_network
        self.name = name
        self.id = _id
        self.mac = mac
        self.type = _type
        self.brightness = 0
        self.color_temp = 0
        self.red = 0
        self.green = 0
        self.blue = 0
        self.rgb = False
        self.online = False
        self._supports_rgb = None
        self._supports_temperature = None
        self._is_plug = None
        self.reported_temp = 0

    async def set_temperature(self, color_temp):
        if not self.online:
            return False
        if await self.network.send_packet(self.id, 0xE2, [0x05, color_temp]):
            self.color_temp = color_temp
            return True
        return False

    async def set_rgb(self, red, green, blue):
        if not self.online:
            return False
        if await self.network.send_packet(self.id, 0xE2, [0x04, red, green, blue]):
            self.red = red
            self.green = green
            self.blue = blue
            return True
        return False

    async def set_brightness(self, brightness):
        if not self.online:
            return False
        if await self.network.send_packet(self.id, 0xD2, [brightness]):
            self.brightness = brightness
            return True
        return False

    async def set_power(self, power):
        if not self.online:
            return False
        return await self.network.send_packet(self.id, 0xD0, [int(power)])

    @property
    def is_plug(self) -> bool:
        if self._is_plug is not None:
            return self._is_plug
        if self.type is None:
            return False
        return self.type in CyncDevice.Capabilities["PLUG"]

    @is_plug.setter
    def is_plug(self, value: bool) -> None:
        self._is_plug = value

    @property
    def supports_rgb(self) -> bool:
        if self._supports_rgb is not None:
            return self._supports_rgb
        if self._supports_rgb or self.type in CyncDevice.Capabilities["RGB"]:
            return True
        return False

    @supports_rgb.setter
    def supports_rgb(self, value: bool) -> None:
        self._supports_rgb = value

    @property
    def supports_temperature(self) -> bool:
        if self._supports_temperature is not None:
            return self._supports_temperature
        if self.supports_rgb or self.type in CyncDevice.Capabilities["COLORTEMP"]:
            return True
        return False

    @supports_temperature.setter
    def supports_temperature(self, value: bool) -> None:
        self._supports_temperature = value
