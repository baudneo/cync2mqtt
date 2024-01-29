#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import os
import sys
import time
from multiprocessing import Process, Value
from pathlib import Path
from signal import SIGINT, SIGTERM, signal
from typing import Optional

import yaml
from amqtt.client import MQTTClient
from amqtt.mqtt.constants import QOS_0, QOS_1

from . import acync

logger = logging.getLogger('cync2mqtt')
logger.addHandler(logging.NullHandler())


class Cync2MQTT:
    """docstring for cync2mqtt.py"""

    def __init__(self, configdict, **kwargs):
        self.mqtt: Optional[MQTTClient] = None
        self.mqtt_url: Optional[str] = configdict["mqtt_url"]
        self.configdict: Optional[dict] = configdict
        self.mesh_networks: Optional[acync] = None
        self.ha_topic: str = (
            configdict["ha_mqtt_topic"]
            if "ha_mqtt_topic" in configdict
            else "homeassistant"
        )
        self.topic: str = (
            configdict["mqtt_topic"] if "mqtt_topic" in configdict else "acyncmqtt"
        )
        self.watch_time = kwargs.get("watchtime", None)

        # hardcode for now
        self.cync_mink: int = 2000
        self.cync_maxk: int = 7000
        self.cync_min_mired: int = int(1e6 / self.cync_maxk + 0.5)
        self.cync_max_mired: int = int(1e6 / self.cync_mink + 0.5)

        self.hass_minct: int = int(1e6 / 5000 + 0.5)
        self.hass_maxct: int = int(1e6 / self.cync_mink + 0.5)

    def hassct_to_tlct(self, ct):
        # convert HASS mired range to percent range (Telink mesh)
        # Cync light is 2000K (1%) to 7000K (100%)
        # Cync light is cync_max_mired (1%) to cync_min_mired (100%)
        scale = 99 / (self.cync_max_mired - self.cync_min_mired)
        return 100 - int(scale * (ct - self.cync_min_mired))

    def tlct_to_hassct(self, ct):
        # Convert Telink mesh percent range (1-100) to HASS mired range
        # Cync light is 2000K (1%) to 7000K (100%)
        # Cync light is cync_max_mired (1%) to cync_min_mired (100%)
        if ct == 0:
            return self.cync_max_mired
        if ct > 100:
            return self.cync_min_mired

        scale = (self.cync_min_mired - self.cync_max_mired) / 99
        return self.cync_max_mired + int(scale * (ct - 1))

    async def pub_worker(self, pubqueue):
        while True:
            (asyncobj, devicestatus) = await pubqueue.get()
            logger.debug(f"pub_worker - device_status: {devicestatus}")

            # TODO - add somesort of timestamp her to toss out messages that are too old

            powerstatus = "ON" if devicestatus.brightness > 0 else "OFF"
            devicename = f"{devicestatus.name}/{devicestatus.id}"
            device = asyncobj.devices[devicename]
            if device.is_plug:
                logger.debug(
                    f"pub_worker mqtt publish: {self.topic}/status/{devicename}  {powerstatus}"
                )
                try:
                    message = await self.mqtt.publish(
                        f"{self.topic}/status/{devicename}",
                        powerstatus.encode(),
                        qos=QOS_0,
                    )
                except:
                    logger.error("Unable to publish mqtt message... skipped")

            else:
                devicestate = {
                    "brightness": devicestatus.brightness,
                    "state": powerstatus,
                }
                if (
                    device.supports_rgb
                    and devicestatus.red | devicestatus.blue | devicestatus.green
                ):
                    devicestate["color_mode"] = "rgb"
                    devicestate["color"] = {
                        "r": devicestatus.red,
                        "g": devicestatus.green,
                        "b": devicestatus.blue,
                    }
                    if device.supports_temperature and devicestatus.color_temp > 0:
                        devicestate["color_mode"] = "rgbw"
                        devicestate["color_temp"] = self.tlct_to_hassct(
                            devicestatus.color_temp
                        )

                elif device.supports_temperature:
                    devicestate["color_mode"] = "color_temp"
                    devicestate["color_temp"] = self.tlct_to_hassct(
                        devicestatus.color_temp
                    )

                logger.debug(
                    f"pub_worker  mqtt publish: {self.topic}/status/{devicename}  "
                    + json.dumps(devicestate)
                )
                try:
                    message = await self.mqtt.publish(
                        f"{self.topic}/status/{devicename}",
                        json.dumps(devicestate).encode(),
                        qos=QOS_0,
                    )
                except:
                    logger.error("Unable to publish mqtt message... skipped")

                # ,json.dumps(devicestatus._asdict()).encode(), qos=QOS_0)

            # Notify the queue that the "work item" has been processed.
            pubqueue.task_done()

    async def homeassistant_discovery(self):
        logger.debug("Doing homeassistant_discovery")
        for devicename, device in self.mesh_networks.devices.items():
            if device.is_plug:
                switchconfig = {
                    "name": device.name,
                    "command_topic": self.topic + "/set/" + devicename,
                    "state_topic": self.topic + "/status/" + devicename,
                    "avty_t": self.topic + "/availability/" + devicename,
                    "pl_avail": "online",
                    "pl_not_avail": "offline",
                    "unique_id": device.mac,
                }
                logger.debug(
                    f"mqtt publish: {self.ha_topic}/switch/{devicename}/config  "
                    + json.dumps(switchconfig)
                )
                try:
                    message = await self.mqtt.publish(
                        f"{self.ha_topic}/switch/{devicename}/config",
                        json.dumps(switchconfig).encode(),
                        qos=QOS_1,
                    )
                except:
                    logger.error("Unable to publish mqtt message... skipped")

            else:
                lightconfig = {
                    "name": device.name,
                    "command_topic": self.topic + "/set/" + devicename,
                    "state_topic": self.topic + "/status/" + devicename,
                    "avty_t": self.topic + "/availability/" + devicename,
                    "pl_avail": "online",
                    "pl_not_avail": "offline",
                    "unique_id": device.mac,
                    "schema": "json",
                    "brightness": True,
                    "brightness_scale": 100,
                }
                if device.supports_temperature or device.supports_rgb:
                    lightconfig["color_mode"] = True
                    lightconfig["supported_color_modes"] = []
                    if device.supports_temperature:
                        lightconfig["supported_color_modes"].append("color_temp")
                        lightconfig["max_mireds"] = self.hass_maxct
                        lightconfig["min_mireds"] = self.hass_minct
                    if device.supports_rgb:
                        lightconfig["supported_color_modes"].append("rgb")

                logger.debug(
                    f"mqtt publish: {self.ha_topic}/light/{devicename}/config  "
                    + json.dumps(lightconfig)
                )
                try:
                    message = await self.mqtt.publish(
                        f"{self.ha_topic}/light/{devicename}/config",
                        json.dumps(lightconfig).encode(),
                        qos=QOS_1,
                    )
                except:
                    logger.error("Unable to publish mqtt message... skipped")

    async def publish_devices(self):
        logger.debug("publish_devices:")
        for devicename, device in self.mesh_networks.devices.items():
            deviceconfig = {
                "name": device.name,
                "id": device.id,
                "mac": device.mac,
                "is_plug": device.is_plug,
                "supports_rgb": device.supports_rgb,
                "supports_temperature": device.supports_temperature,
                "online": device.online,
                "brightness": device.brightness,
                "red": device.red,
                "green": device.green,
                "blue": device.blue,
                "color_temp": self.tlct_to_hassct(device.color_temp),
            }
            try:
                logger.debug(
                    f"mqtt publish: {self.ha_topic}/devices/{devicename}  "
                    + json.dumps(deviceconfig)
                )
                message = await self.mqtt.publish(
                    f"{self.ha_topic}/devices/{devicename}",
                    json.dumps(deviceconfig).encode(),
                    qos=QOS_1,
                )
            except:
                logger.error("Unable to publish mqtt message... skipped")

    async def sub_worker(self, subqueue):
        while True:
            message = await subqueue.get()

            if message is None:
                continue

            try:
                packet = message.publish_packet
            except:
                continue

            logger.debug(
                "sub_worker: %s => %s"
                % (packet.variable_header.topic_name, str(packet.payload.data))
            )
            topic = packet.variable_header.topic_name.split("/")
            if len(topic) == 4:
                if topic[1] == "set":
                    devicename = "/".join(topic[2:4])
                    device = self.mesh_networks.devices[devicename]
                    if packet.payload.data.startswith(b"{"):
                        try:
                            jsondata = json.loads(packet.payload.data)
                        except:
                            logger.error("bad json message: {jsondata}")
                            continue
                        # print(jsondata)
                        if "state" in jsondata and (
                            "brightness" not in jsondata or device.brightness < 1
                        ):
                            if jsondata["state"].upper() == "ON":
                                await device.set_power(True)
                            else:
                                await device.set_power(False)
                        if "brightness" in jsondata:
                            lum = int(jsondata["brightness"])
                            if lum < 5 and lum > 0:
                                lum = 5  # Workaround issue noted by zimmra
                            await device.set_brightness(lum)
                        if "color_temp" in jsondata:
                            await device.set_temperature(
                                self.hassct_to_tlct(int(jsondata["color_temp"]))
                            )
                        if "color" in jsondata:
                            color = []
                            for rgb in ("r", "g", "b"):
                                if rgb in jsondata["color"]:
                                    color.append(int(jsondata["color"][rgb]))
                                else:
                                    color.append(0)
                            await device.set_rgb(*color)
                    elif packet.payload.data.upper() == b"ON":
                        await device.set_power(True)
                    elif packet.payload.data.upper() == b"OFF":
                        await device.set_power(False)
                # make sure next commmand doesn't come too fast
                await asyncio.sleep(0.1)
            elif len(topic) == 2:
                if topic[1] == "shutdown":
                    logger.info("Shutdown requested")
                    os.kill(os.getpid(), SIGTERM)
                elif topic[1] == "devices" and packet.payload.data.lower() == b"get":
                    await self.publish_devices()
                elif (
                    topic[0] == self.ha_topic
                    and topic[1] == "status"
                    and packet.payload.data.upper() == b"ONLINE"
                ):
                    await self.homeassistant_discovery()
                    await asyncio.sleep(1)

                    for device in self.mesh_networks.devices.values():
                        device.online = False

                    for network in self.mesh_networks.networks.values():
                        await network.update_status()

                    # Wait a reasonable amount of time for device nodes to report status through the mesh
                    await asyncio.sleep(0.2 * len(self.mesh_networks.devices.keys()))
                    for devicename, device in self.mesh_networks.devices.items():
                        availability = b"online" if device.online else b"offline"
                        message = await self.mqtt.publish(
                            f"{self.topic}/availability/{devicename}",
                            availability,
                            qos=QOS_0,
                        )

            # Notify the queue that the "work item" has been processed.
            subqueue.task_done()
        return True

    async def status_worker(self):
        while True:
            for device in self.mesh_networks.devices.values():
                device.online = False
            for network in self.mesh_networks.networks.values():
                count = 0
                while not await network.update_status():
                    for devicename, device in network.devices.items():
                        availability = b"offline"
                        logger.debug(
                            f"status_worker  mqtt publish: {self.topic}/availability/{devicename}  {availability}"
                        )
                        try:
                            message = await self.mqtt.publish(
                                f"{self.topic}/availability/{devicename}",
                                availability,
                                qos=QOS_0,
                            )
                        except:
                            logger.info("MQTT fail- attempt shutdown!")
                            os.kill(os.getpid(), SIGINT)
                    if count > 3:
                        # Take drastic action
                        logger.info("Communication timeout- attempt shutdown!")
                        os.kill(os.getpid(), SIGINT)

                    logger.info(
                        "Status update failed!  - waiting two minutes to try again"
                    )

                    # Wait 2 minutes and try again
                    await asyncio.sleep(120)
                    count += 1
                    logger.info("Retry status update")

            # Wait a reasonable amount of time for device nodes to report status through the mesh
            await asyncio.sleep(0.2 * len(self.mesh_networks.devices.keys()))

            for devicename, device in self.mesh_networks.devices.items():
                availability = b"online" if device.online else b"offline"
                logger.debug(
                    f"status_worker  mqtt publish: {self.topic}/availability/{devicename}  {availability}"
                )
                message = await self.mqtt.publish(
                    f"{self.topic}/availability/{devicename}", availability, qos=QOS_0
                )
            if self.watch_time is not None:
                self.watch_time.value = int(time.time())
            await asyncio.sleep(300)

    @staticmethod
    async def callback_routine(pubqueue: asyncio.Queue, asyncobj, devicestatus):
        pubqueue.put_nowait((asyncobj, devicestatus))

    async def run_mqtt(self):
        try:
            # self.mqtt = MQTTClient(config={'reconnect_retries':-1, 'reconnect_max_interval': 60})
            self.mqtt = MQTTClient(
                config={"reconnect_retries": 0, "auto_reconnect": False}
            )
            ret = await self.mqtt.connect(self.mqtt_url)
        except Exception as ce:
            logger.error("MQTT Connection failed: %s" % ce)
            # raise Exception("MQTT Connection failed: %s" % ce)
            try:
                await self.mqtt.disconnect()
            except:
                pass
            logger.error("Will attempt reconnect in 10 minutes")
            return

        pubqueue = asyncio.Queue()
        subqueue = asyncio.Queue()

        #        self.meshnetworks=acync(self.cloudjson,log=logger,callback=lambda asyncobj,devicestatus,q=pubqueue: q.put_nowait((asyncobj,devicestatus)))

        import functools

        self.mesh_networks = acync(
            callback=functools.partial(pubqueue, self.callback_routine)
        )
        self.mesh_networks.populate_from_configdict(self.configdict)
        # announce to homeassistant discovery
        await self.homeassistant_discovery()

        # seed everything offline
        for devicename, device in self.mesh_networks.devices.items():
            availability = b"offline"
            message = await self.mqtt.publish(
                f"{self.topic}/availability/{devicename}", availability, qos=QOS_0
            )

        meshnetworknames = await self.mesh_networks.connect()
        if len(meshnetworknames) > 0:
            logger.info("Connected to network(s): " + ",".join(meshnetworknames))
        else:
            logger.error("No mesh network connections!")
            try:
                await self.mqtt.disconnect()
            except:
                pass
            return

        tasks = []
        tasks.append(asyncio.create_task(self.pub_worker(pubqueue)))
        subtask = asyncio.create_task(self.sub_worker(subqueue))
        tasks.append(subtask)
        tasks.append(asyncio.create_task(self.status_worker()))

        # add signal handler to catch when it's time to shutdown
        loop = asyncio.get_running_loop()
        main_task = asyncio.current_task()
        for signal in [SIGINT, SIGTERM]:
            loop.add_signal_handler(signal, main_task.cancel)

        await self.mqtt.subscribe(
            [
                (f"{self.topic}/set/#", QOS_1),
                (f"{self.topic}/devices", QOS_1),
                (f"{self.topic}/shutdown", QOS_1),
                (f"{self.ha_topic}/status", QOS_1),
            ]
        )
        try:
            while True:
                message = await self.mqtt.deliver_message()
                if message:
                    subqueue.put_nowait(message)
        except asyncio.CancelledError:
            logger.info("Termination signal received")
        except Exception as ce:
            logger.error("Client exception: %s" % ce)

        logger.info("Shutting down")
        try:
            await self.mqtt.unsubscribe(
                [
                    f"{self.topic}/set/#",
                    f"{self.topic}/devices",
                    f"{self.topic}/shutdown",
                    f"{self.ha_topic}/status",
                ]
            )
            await self.mqtt.disconnect()
        except:
            pass

        # Wait until the queue is fully processed.
        await pubqueue.join()
        await subqueue.join()

        # shutdown meshnetworks
        await self.mesh_networks.disconnect()

        # Cancel our worker tasks.
        for task in tasks:
            task.cancel()
        # Wait until all worker tasks are cancelled.
        await asyncio.gather(*tasks, return_exceptions=True)
