# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib import hub
from queue import Queue
import time
import threading
import json

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

class Enforcement_thread(threading.Thread):
    def __init__(self, app):
        super().__init__(daemon=True)
        self.app = app
        self.blacklist = []
        self.queue = Queue()
        self.meter_id = 1

    def slow(self, mac):
        for dp in self.app.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            bands = [parser.OFPMeterBandDrop(rate=1000, burst_size=200)]
            meter_mod = parser.OFPMeterMod(
                dp, ofproto.OFPMC_ADD, ofproto.OFPMF_KBPS, self.meter_id, bands
            )
            dp.send_msg(meter_mod)

            match = parser.OFPMatch(eth_src=mac)
            inst = [
                parser.OFPInstructionMeter(self.meter_id),
                parser.OFPInstructionGotoTable(1),
            ]

            mod = parser.OFPFlowMod(
                datapath=dp,
                table_id=0,
                priority=100,
                match=match,
                instructions=inst
            )
            dp.send_msg(mod)
            print(f" [Enforcement] Rallentamento (meter) attivo per {mac}")

    def unslow(self, mac):
        for dp in self.app.datapaths.values():
            ofproto = dp.ofproto
            parser = dp.ofproto_parser

            match = parser.OFPMatch(eth_src=mac)
            mod = parser.OFPFlowMod(
                datapath=dp,
                table_id=0,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            dp.send_msg(mod)
            print(f" [Enforcement] Fine rallentamento per {mac}")

    def block(self, mac, tipo):
        self.queue.put((tipo, mac))

    def run(self):
        while True:
            tipo, mac = self.queue.get()
            for dp in self.app.datapaths.values():
                ofproto = dp.ofproto
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_src=mac)
                instructions = []

                flow_mod = parser.OFPFlowMod(
                    datapath=dp,
                    priority=2,
                    match=match,
                    instructions=instructions,
                    command=ofproto.OFPFC_ADD,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    flags=ofproto.OFPFF_SEND_FLOW_REM
                )
                dp.send_msg(flow_mod)

            with open("liste.json", "r") as f:
                data = json.load(f)

            data[tipo].append(mac)

            with open("liste.json", "w") as f:
                json.dump(data, f, indent=4)

            print(RED + "Blocked traffic from %s " + RESET, mac)
