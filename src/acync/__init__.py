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

from .main import ACync, xlinkException, LOG_NAME as ACYNC_LOG_NAME, randomLoginResource
from .Cync2MQTT import Cync2MQTT, MQTT_DEBUG, LOG_NAME as C2M_LOG_NAME
__all__ = ["ACync", "xlinkException", "ACYNC_LOG_NAME", "randomLoginResource", "Cync2MQTT", "MQTT_DEBUG", "C2M_LOG_NAME"]
__version__ = "0.0.1a1"
