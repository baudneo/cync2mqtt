# CYNC / C-GE bluetooth mesh light control implemented with BLEAK: https://github.com/hbldh/bleak
import asyncio
import concurrent.futures
import functools
import logging
import os
import queue
import random
import signal
from collections import namedtuple
from typing import Optional, Union, Dict, Tuple, NamedTuple, overload

import bluepy.btle
import uvloop
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
SCAN_TIMEOUT: int = 10
CONNECT_TIMEOUT: int = 10
VENDOR: int = 0x0211
CONNECT_ATTEMPTS: int = 50


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
    noti_id: int = 0

    def __init__(self, notify_queue: queue.Queue):
        bluepy.btle.DefaultDelegate.__init__(self)
        self.notify_queue = notify_queue

    def handleNotification(self, cHandle, data):
        self.noti_id += 1
        logger.debug(
            f"btle gatt: bluepy: handleNotification: adding to notification queue with id: %d"
            % self.noti_id
        )
        self.notify_queue.put_nowait((cHandle, data, self.noti_id))
        logger.debug(
            f"btle gatt: bluepy: handleNotification: added to notification queue with id: %d"
            % self.noti_id
        )



class BtLEGATT(object):
    def __init__(
        self,
        mac: str,
        uselib: Optional[str] = None,
        friendly_name: Optional[str] = None,
    ):
        if uselib is None:
            uselib = "bleak"
        self.mac_rssi: Optional[int] = None
        self.mac: str = mac
        self.is_connected: Optional[bool] = None
        self.notify_tasks: Optional[list] = None
        self.notify_queue: Optional[queue.Queue] = None
        self._notifycallbacks: dict = {}
        self.loop: Union[
            asyncio.AbstractEventLoop, uvloop.Loop
        ] = asyncio.get_running_loop()
        self.bluepy_lock: asyncio.Lock = asyncio.Lock()
        self._uuid_chars: dict = {}
        self.client: Union[BleakClient, bluepy.btle.Peripheral, None]
        self._bt_lib: Optional[str] = uselib
        self.lp: str = f"btle gatt:{self._bt_lib}:"
        self.discovered_devices: Optional[
            Dict[str, Union[Tuple[BLEDevice, AdvertisementData]]]
        ] = {}
        self.friendly_name: Optional[str] = friendly_name

        if uselib == "bleak":
            self.client = None

        elif uselib == "bluepy":
            logger.info(f"btle gatt: using bluepy library")
            # dont pass a device address to the constructor, we'll connect later
            self.client = bluepy.btle.Peripheral()
        else:
            raise ValueError("btle_gatt: bluetooth library: %s not supported" % uselib)

    async def notify_worker(self):
        pool = concurrent.futures.ThreadPoolExecutor(1)
        logger.debug(
            f"btle_gatt:{self._bt_lib}: notify_worker starting, waiting for notify_queue items..."
        )
        while True:
            (handle, data, noti_id) = await self.loop.run_in_executor(
                pool, self.notify_queue.get
            )
            logger.debug(
                f"btle_gatt:{self._bt_lib}: notify_worker: got item from notify_queue => noti_id: {noti_id} "
                f"// data: {data}"
            )
            if handle in self._notifycallbacks:
                # logger.debug(
                #     f"btle_gatt:{self._bt_lib}: notify_worker: calling callback for handle: {handle}"
                # )
                await self._notifycallbacks[handle](handle, data, noti_id)
            else:
                logger.warning(
                    f"btle_gatt:{self._bt_lib}: notify_worker: No callback for handle: {handle}"
                )

            await self.loop.run_in_executor(pool, self.notify_queue.task_done)

    async def notify_waiter(self):
        """A bluepy specific method to wait for notifications."""
        pool = concurrent.futures.ThreadPoolExecutor(1)
        while True:
            await asyncio.sleep(0.25)
            async with self.bluepy_lock:
                await self.loop.run_in_executor(
                    pool, self.client.waitForNotifications, 0.25
                )

    async def discover(self):
        if isinstance(self.client, bluepy.btle.Peripheral):
            scanner = bluepy.btle.Scanner()
            self.discovered_devices = scanner.scan(SCAN_TIMEOUT)
            if not self.discovered_devices:
                logger.debug(f"btle_gatt:{self._bt_lib}: no devices discovered!")

            else:
                logger.debug(
                    f"btle_gatt:{self._bt_lib}: discovered {len(self.discovered_devices)} "
                    f"devices: {self.discovered_devices}"
                )
        else:
            self.discovered_devices = await BleakScanner.discover(
                timeout=SCAN_TIMEOUT, return_adv=True
            )
            if not self.discovered_devices:
                logger.debug(f"btle_gatt:{self._bt_lib}: no devices discovered!")
            else:
                logger.debug(
                    f"btle_gatt:{self._bt_lib}: discovered {len(self.discovered_devices)} "
                    f"devices: {self.discovered_devices}"
                )
        return self.discovered_devices

    async def connect(self, timeout=CONNECT_TIMEOUT):
        # logger.debug(f"btle_gatt:{self._bt_lib}: connect called for device: {self.mac} [{self.friendly_name}]")
        if self.is_connected:
            logger.debug(f"{self.lp} already connected to {self.mac}")
            return
        self._uuid_chars = {}

        if isinstance(self.client, bluepy.btle.Peripheral):
            try:
                async with self.bluepy_lock:
                    await self.loop.run_in_executor(
                        concurrent.futures.ThreadPoolExecutor(1),
                        functools.partial(
                            self.client.connect,
                            self.mac,
                            addrType=bluepy.btle.ADDR_TYPE_PUBLIC,
                        ),
                    )

            except bluepy.btle.BTLEDisconnectError as bt_e:
                exc = True
                if str(bt_e).startswith("Failed to connect to peripheral"):
                    exc = False
                logger.error(
                    f"btle_gatt:{self._bt_lib}: Unable to connect to device: {self.mac} [{self.friendly_name}] -> {bt_e}",
                    exc_info=exc,
                )
                return False
            except Exception as e:
                logger.error(
                    f"btle_gatt:{self._bt_lib}: Unable to connect to device: {self.mac} [{self.friendly_name}] -> {e}",
                    exc_info=True,
                )
                return False
            else:
                self.notify_queue = queue.Queue()
                self.notify_tasks = []
                self.notify_tasks.append(asyncio.create_task(self.notify_worker()))
                self.client.setDelegate(BluePyDelegate(self.notify_queue))
                status = self.client.status()
                result = status.get("state") == ["conn"]
                self.is_connected = result

            return result
        else:
            # bleak
            # device = None
            # if self.mac not in self.discovered_devices:
            #     await self.discover()
            # if self.mac in self.discovered_devices:
            #     device = self.discovered_devices[self.mac][0]
            #     advertisement = self.discovered_devices[self.mac][1]
            #     self.mac_rssi = advertisement.rssi
            #     logger.debug(f"btle_gatt:{self.use_bt_lib}: Scanning found device: {self.mac} [{self.friendly_name}] - "
            #                  f" {advertisement} - Connect Timeout: {timeout}")
            # if device is None:
            #     logger.error(
            #         f"btle_gatt:{self.use_bt_lib}: Scanning could not find device: {self.mac} [{self.friendly_name}]"
            #     )
            #     return

            self.client = BleakClient(self.mac)
            status = await self.client.connect(timeout=timeout)
            self.is_connected = status
            return status

    async def bluepy_get_char_from_uuid(self, uuid):
        """A bluepy specific method to get a characteristic from a UUID."""
        if uuid in self._uuid_chars:
            return self._uuid_chars[uuid]
        else:
            async with self.bluepy_lock:
                char = (
                    await self.loop.run_in_executor(
                        concurrent.futures.ThreadPoolExecutor(1),
                        functools.partial(self.client.getCharacteristics, uuid=uuid),
                    )
                )[0]
                self._uuid_chars[uuid] = char
            return char

    async def write_gatt_char(
        self, uuid: Union[str, bytes, bytearray], data, withResponse=False
    ):
        """Write a characteristic to the device."""
        if isinstance(self.client, bluepy.btle.Peripheral):
            char = await self.bluepy_get_char_from_uuid(uuid)
            try:
                async with self.bluepy_lock:
                    result = await self.loop.run_in_executor(
                        concurrent.futures.ThreadPoolExecutor(1),
                        functools.partial(char.write, data, withResponse=withResponse),
                    )
                    logger.debug(f"btle_gatt:{self._bt_lib}: write_gatt_char: {result}")
            except bluepy.btle.BTLEInternalError as bt_ie:
                logger.error(
                    f"btle_gatt:{self._bt_lib}: Unable to write to device: {self.mac} [{self.friendly_name}] -> {bt_ie}",
                    exc_info=True,
                )
                return False


            return result
        elif isinstance(self.client, BleakClient):
            return await self.client.write_gatt_char(uuid, data, withResponse)

    async def read_gatt_char(self, uuid):
        if isinstance(self.client, bluepy.btle.Peripheral):
            # get characteristic from uuid
            char = await self.bluepy_get_char_from_uuid(uuid)
            async with self.bluepy_lock:
                result = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1), char.read
                )
            return result
        elif isinstance(self.client, BleakClient):
            return await self.client.read_gatt_char(uuid)

    async def disconnect(self):
        if self.notify_tasks is not None:
            for notifytask in self.notify_tasks:
                notifytask.cancel()

        if isinstance(self.client, bluepy.btle.Peripheral):
            async with self.bluepy_lock:
                result = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1), self.client.disconnect
                )
            return result
        else:
            return await self.client.disconnect()

    async def start_notify(
        self, uuid: str, callback_handler: "ATELinkMesh.callback_handler"
    ):
        if isinstance(self.client, bluepy.btle.Peripheral):
            char = await self.bluepy_get_char_from_uuid(uuid)
            async with self.bluepy_lock:
                handle = await self.loop.run_in_executor(
                    concurrent.futures.ThreadPoolExecutor(1), char.getHandle
                )
            self._notifycallbacks[handle] = callback_handler
            self.notify_tasks.append(asyncio.create_task(self.notify_waiter()))
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
        bt_lib: Optional[str] = None,
    ):
        self.vendor = vendor
        self.mesh_macs = (
            {x: (0, "unknown", 30) for x in mesh_macs}
            if type(mesh_macs) is list
            else mesh_macs
        )
        self.name: str = name
        self.password: str = password
        self.packet_count = random.randrange(0xFFFF)
        self.mac_data = None
        self.sk = None
        self.client: Optional[BtLEGATT] = None
        self.current_mac: Optional[str] = ""
        # Handle None and empty string
        if not bt_lib:
            self.use_bt_lib = "bleak"
        else:
            self.use_bt_lib = bt_lib

    async def __aenter__(self):
        logger.debug("telink mesh: __aenter__")
        await self.connect()
        return self

    async def __aexit__(self, exc_t, exc_v, exc_tb):
        logger.debug("telink mesh: __aexit__")
        await self.disconnect()

    async def disconnect(self):
        logger.debug("telink mesh: disconnect called")
        if self.client is not None:
            try:
                await self.client.disconnect()
            except Exception as e:
                logger.info("telink: disconnect exception -> %s" % e, exc_info=True)
            self.client = None

    async def callback_handler(self, sender, data):
        print(
            "{0}: {1}".format(
                sender, decrypt_packet(self.sk, self.mac_data, list(data))
            )
        )
        logger.debug(
            f"telink mesh: callback_handler: {sender = } - {decrypt_packet(self.sk, self.mac_data, list(data)) = }"
        )

    async def connect(self):
        logger.debug("telink mesh:connect: called")
        self.mac_data = None
        self.sk = None
        total_macs = len(self.mesh_macs)
        skipped_macs = 0

        for retry in range(CONNECT_ATTEMPTS):
            if self.sk is not None:
                # Assuming we are already connected
                break
            # self.mesh_macs schema -> { MAC[str] : (priority[int], friendly_name[str], timeout[int]) }
            for mac_idx, mac in enumerate(
                sorted(self.mesh_macs, key=lambda x: self.mesh_macs[x][0])
            ):
                mac_priority = self.mesh_macs[mac][0]
                mac_friendly_name = self.mesh_macs[mac][1]
                mac_timeout = self.mesh_macs[mac][2]

                # if priority is less than 0, skip it
                if mac_priority < 0:
                    # logger.warning(
                    #     f"telink mesh:connect: Skipping, priority < 0 -> MAC: {mac} [{mac_friendly_name}]"
                    # )
                    skipped_macs += 1
                    continue
                _t_macs = total_macs - skipped_macs
                logger.debug(
                    f"telink mesh:connect: attempt: {retry + 1}/{CONNECT_ATTEMPTS} to MAC "
                    f"({mac_idx + 1}/{_t_macs}): {mac} [{mac_friendly_name}]"
                )
                self.client = BtLEGATT(
                    mac, uselib=self.use_bt_lib, friendly_name=mac_friendly_name
                )

                try:
                    # BtLEGATT.connect wrapper
                    await self.client.connect()
                except Exception as e:
                    # increment priority
                    mac_priority += 1
                    self.mesh_macs[mac] = (mac_priority, mac_friendly_name, mac_timeout)
                    logger.warning(
                        "telink mesh:connect: EXCEPTION! Unable to CONNECT to device: %s [%s] --> %s"
                        % (mac, mac_friendly_name, e),
                        exc_info=True,
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
                        self.pairing_char, bytes(packet), True
                    )
                    await asyncio.sleep(0.3)
                    data2 = await self.client.read_gatt_char(self.pairing_char)
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
                        # Start the notification listener
                        await self.client.start_notify(
                            self.notification_char, self.callback_handler
                        )
                        await asyncio.sleep(0.3)
                        # Enable notifications
                        await self.client.write_gatt_char(
                            self.notification_char, bytes([0x1]), True
                        )
                        await asyncio.sleep(0.3)
                        _ = await self.client.read_gatt_char(self.notification_char)
                    except Exception as e:
                        logger.critical(
                            "telink mesh:connect: Unable to communicate with mesh mac for notifications: %s -> %s"
                            % (mac, e),
                        )
                        await self.client.disconnect()
                        self.sk = None
                        continue
                    else:
                        logger.info(
                            f"telink mesh:connect: Connected to mesh ID: {self.name} via MAC: {mac} [{mac_friendly_name}]"
                        )

                    break

        return self.sk is not None

    async def update_status(self):
        if self.sk is None:
            logger.info(
                "telink mesh:update_status: self.sk is None, Attempt re-connect..."
            )
            if not await self.connect():
                return False

        # logger.debug(f"telink mesh:update_status: current_mac: {self.current_mac}")
        attempts = 3
        ok = False
        for _try in range(attempts):
            if ok:
                logger.debug(
                    f"telink mesh:update_status: Attempt successful!"
                )
                break
            try:
                logger.debug(
                    f"telink mesh:update_status: Attempt #{_try+1}/{attempts} to call self.client.write_gatt_char"
                )
                await self.client.write_gatt_char(
                    self.notification_char, bytes([0x1]), True
                )
                await asyncio.sleep(0.3)
                r_ = await self.client.read_gatt_char(self.notification_char)
                logger.debug(
                    f"telink mesh:update_status: return from reading notification UUID =>  {r_}"
                )
                ok = True
            except Exception as e:
                logger.info(
                    "update_status - Unable to communicate with mesh, retry... -> %s"
                    % e,
                    exc_info=True,
                )

                logger.debug(f"Sending SIGINT to try and force reconnect")
                os.kill(os.getpid(), signal.SIGINT)

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
            logger.debug(
                f"telink mesh:send_packet: Not online! - Attempt re-connect..."
            )
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

        for trycount in range(3):
            try:
                await self.client.write_gatt_char(
                    Network.control_char, bytes(enc_packet)
                )
                # bluez/bleak do not seem to detect a disconnection by physical/external means
                # send packet catches it when a command is issued via mqtt ->
                # "send_packet - Unable to connect for sending to mesh -> Service Discovery has not been performed yet"
            except Exception as e:
                logger.warning(
                    f"send_packet - Unable to connect for sending to mesh -> %s" % e,
                    exc_info=True,
                )
                if trycount < 2:
                    logger.info(f"send_packet - Attempt re-connect #{trycount+1}...")
                    self.mesh_macs[self.current_mac][0] += 1
                    self.current_mac = ""
                    await asyncio.sleep(0.1)
                    logger.debug("send_packet - Disconnect...")
                    await self.disconnect()
                    await asyncio.sleep(0.1)
                    logger.debug("send_packet - Disconnected... reconnecting...")
                    await self.connect()
                    logger.debug("send_packet - Reconnected...")
                else:
                    logger.error(f"send_packet - Retries exhausted...")
                    return False
            break
        return True


class DeviceStatus(NamedTuple):
    """
    Data structure for device status.

    :param str name: The name of the device
    :param int id: The device ID
    :param int brightness: The brightness of the device (0-100)
    :param bool rgb: True if the device supports RGB, False if it only supports tunable white
    :param int red: The red value of the device (0-255)
    :param int green: The green value of the device (0-255)
    :param int blue: The blue value of the device (0-255)
    :param int color_temp: The color temperature of the device (0-255)
    """

    name: str
    id: int
    brightness: int
    rgb: bool
    red: int
    green: int
    blue: int
    color_temp: int
    notification_id: Optional[int] = None


class Network(ATELinkMesh):
    # device_status = namedtuple(
    #     "DeviceStatus",
    #     ["name", "id", "brightness", "rgb", "red", "green", "blue", "color_temp"],
    # )
    device_status = DeviceStatus

    def __init__(
        self,
        mesh_macs: Dict[str, Tuple[int, str, int]],
        name: str,
        password: str,
        bt_lib: Optional[str] = None,
        **kwargs,
    ):
        self.callback = kwargs.get("callback", None)
        super().__init__(VENDOR, mesh_macs, name, password, bt_lib)

    async def callback_handler(self, sender: int, data: bytes, noti_id: int):
        """Handle incoming RAW notifications from the mesh network. Decrypt and parse the data. Pass the data up the callback stack"""
        lp = "bt noti:id=%d:" % noti_id
        if self.callback is None:
            logger.warning(f"{lp} No callback defined for incoming notifications")
            return
        data = list(data)
        if len(data) < 19:
            logger.warning(
                f"{lp} Incoming notification too short: {len(data)} bytes (Need 19)"
            )
            return
        data = decrypt_packet(self.sk, self.mac_data, data)
        logger.debug(f"{lp} Full Decrypted data: {data}")
        # weird issue where it recieves 0xEA (234) instead of 0xDC (220) for a bt plug that says it is offline
        # Allowing 234 gets wonky data; plug brightness set to 80% instead of 100% for a turn on notification.
        _cmd = data[7]

        responses = data[10:18]
        any_resp = False
        both_resp = False
        _resps = []
        for i in (0, 4):
            response = responses[i : i + 4]
            _resps.append(response)
            if response[1] == 0:
                # logger.debug(f"{lp} Response is empty based on response[1] == 0 -- {response = }")
                continue
            if any_resp is True:
                both_resp = True
            any_resp = True
            _id = response[0]
            unknown_attr = response[1]
            brightness = response[2]
            cct_rgb = response[3]
            (red, green, blue) = (0, 0, 0)
            color_temp = 0
            logger.debug(
                f"{lp} {response} => device_id: {_id} // brightness: {brightness} // UNKNOWN: {unknown_attr}"
            )
            if brightness >= 128:
                # RGB data in response
                brightness = brightness - 128
                red = int(((cct_rgb & 0xE0) >> 5) * 255 / 7)
                green = int(((cct_rgb & 0x1C) >> 2) * 255 / 7)
                blue = int((cct_rgb & 0x3) * 255 / 3)
                rgb = True
                logger.debug(
                    f"{lp} RGB data! {response} => device_id: {_id} // brightness: {brightness} // "
                    f"UNKNOWN: {unknown_attr} // {red = } // {green = } // {blue = }"
                )

            else:
                # Tunable white data OR plug on/off [brightness = 0 or 100/temp = 0] in response
                color_temp = cct_rgb
                rgb = False
                logger.debug(
                    f"{lp} Tunable white data (or plug)! {response} => device_id: {_id} // brightness: {brightness} "
                    f"// UNKNOWN: {unknown_attr} // {color_temp = }"
                )
            if _cmd != 0xDC:
                logger.warning(
                    f"{lp} Unknown command [byte 8]: {hex(_cmd)}/{_cmd} (Expected 0xdc/220), not sending back down "
                    f"the callback stack!"
                )
            else:
                await self.callback(
                    self.device_status(
                        self.name,
                        _id,
                        brightness,
                        rgb,
                        red,
                        green,
                        blue,
                        color_temp,
                        noti_id,
                    )
                )
        if any_resp is False:
            logger.debug(f"{lp} No responses processed => {_resps}")
        else:
            if both_resp is False:
                logger.debug(f"{lp} Only 1/2 responses processed => {responses}")


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
            31, # BTLE only bulb?
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
            31, # BTLE only bulb?
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
            31, # BTLE only bulb?
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
            31,  # BTLE only bulb?
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
        "PLUG": [64, 65, 66, 67, 68], # 86, 51?
        "FAN": [81],
        "MULTIELEMENT": {"67": 2},
    }

    def __init__(
        self,
        mesh_network: Optional[ATELinkMesh],
        name: str,
        _id: int,
        mac: str,
        _type: Optional[int] = None,
    ):
        self.network: Optional[ATELinkMesh] = mesh_network
        self.name: str = name
        self.id: int = _id
        self.mac: str = mac
        self.type: int = _type
        self.brightness: int = 0
        self.color_temp: int = 0
        self.red: int = 0
        self.green: int = 0
        self.blue: int = 0
        self.rgb: bool = False
        self.online: bool = False
        self._supports_rgb: Optional[bool] = None
        self._supports_temperature: Optional[bool] = None
        self._is_plug: Optional[bool] = None
        self.reported_temp: int = 0

    async def set_temperature(self, color_temp: int) -> bool:
        if not self.online:
            return False
        if await self.network.send_packet(self.id, 0xE2, [0x05, color_temp]):
            self.color_temp = color_temp
            return True
        return False

    async def set_rgb(self, red: int, green: int, blue: int) -> bool:
        if not self.online:
            return False
        if await self.network.send_packet(self.id, 0xE2, [0x04, red, green, blue]):
            self.red = red
            self.green = green
            self.blue = blue
            return True
        return False

    async def set_brightness(self, brightness: int) -> bool:
        if not self.online:
            return False
        if await self.network.send_packet(self.id, 0xD2, [brightness]):
            self.brightness = brightness
            return True
        return False

    async def set_power(self, power: int) -> bool:
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
