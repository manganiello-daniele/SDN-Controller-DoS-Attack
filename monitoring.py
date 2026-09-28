#!/usr/bin/python
import threading
import random
import time
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

class monitoring_thread(threading.Thread):
    def __init__(self,app, interval = 1):
        super().__init__(daemon=True)
        self.app = app
        self.stats = {}
        self.rec_res = 0
        self.send_req = 0
        self.time = 0
        self.alarm_flow = {}
        self.datapaths={}
        self.interval=interval
        self.monitor_stats_flow={}
        self.send_req2 ={}
        self.rec_res2={}
        self.counter_switch = {}
        self.counter_mac= {}
        self.monitor_stats_switch = {}
        self.flow_store = {}
        self.switch_store = {}

    def _update_stats_switch(self,ev):
        if ev.msg.datapath.id not in self.counter_switch:
            self.counter_switch[ev.msg.datapath.id]=0

        self.rec_res2 = time.perf_counter()
        body = ev.msg.body
        previous= 0
        self.time = self.interval + (self.rec_res2 - self.send_req2)

        if ev.msg.datapath.id in self.monitor_stats_switch:
            previous = self.monitor_stats_switch[ev.msg.datapath.id]

        self.monitor_stats_switch[ev.msg.datapath.id]= body.byte_count

        if ev.msg.datapath.id not in self.switch_store:
            self.switch_store[ev.msg.datapath.id]= {}
        self.switch_store[ev.msg.datapath.id][self.counter_switch[ev.msg.datapath.id]]=(self.monitor_stats_switch[ev.msg.datapath.id] -previous)/self.time

        if self.counter_switch[ev.msg.datapath.id] == 9:
            self.counter_switch[ev.msg.datapath.id] = 0
        else:
            self.counter_switch[ev.msg.datapath.id] += 1

    def _update_stats_flow(self,ev):
        self.rec_res = time.perf_counter()
        body = ev.msg.body
        lista_mac={}
        previous={}

        self.time = self.interval + (self.rec_res - self.send_req)

        for flow in body:
            match = flow.match
            src_mac = match.get('eth_src')
            if src_mac is None:
                continue
            if src_mac not in lista_mac:
                lista_mac[src_mac]= flow.byte_count
                if ev.msg.datapath.id not in self.counter_mac:
                    self.counter_mac[ev.msg.datapath.id]={}
                if src_mac not in self.counter_mac[ev.msg.datapath.id]:
                    self.counter_mac[ev.msg.datapath.id][src_mac]=0
            else:
                lista_mac[src_mac]=lista_mac[src_mac]+flow.byte_count

        if ev.msg.datapath.id in self.monitor_stats_flow:
            previous = self.monitor_stats_flow[ev.msg.datapath.id]
        else:
            for mac in lista_mac:
                previous[mac]=0

        self.monitor_stats_flow[ev.msg.datapath.id]= {
            mac: bytes
            for mac,bytes in lista_mac.items()
        }

        for mac in self.monitor_stats_flow[ev.msg.datapath.id]:
            if mac not in previous:
                previous[mac]=0

        self.stats[ev.msg.datapath.id] = {}
        for mac in self.monitor_stats_flow[ev.msg.datapath.id]:
            if ev.msg.datapath.id not in self.flow_store:
                self.flow_store[ev.msg.datapath.id]={}
            if mac not in self.flow_store[ev.msg.datapath.id]:
                self.flow_store[ev.msg.datapath.id][mac]= {}
            self.flow_store[ev.msg.datapath.id][mac][self.counter_mac[ev.msg.datapath.id][mac]]=(self.monitor_stats_flow[ev.msg.datapath.id][mac] -previous[mac])/self.time

            if self.counter_mac[ev.msg.datapath.id][mac] == 9:
                self.counter_mac[ev.msg.datapath.id][mac] = 0
            else:
                self.counter_mac[ev.msg.datapath.id][mac] += 1

        for mac, num_bytes in lista_mac.items():
            if previous[mac] != 0:
                self.stats[ev.msg.datapath.id][mac] = (num_bytes - previous[mac]) / self.time
            else:
                self.stats[ev.msg.datapath.id][mac] = num_bytes
                self.alarm_flow[(ev.msg.datapath.id, mac)] = 0

    def request_flow_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        self.send_req = time.perf_counter()

    def request_switch_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()

        req = parser.OFPAggregateStatsRequest(
            datapath=datapath,
            flags=0,
            table_id=ofproto.OFPTT_ALL,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            cookie=0,
            cookie_mask=0,
            match=match
        )
        datapath.send_msg(req)
        self.send_req2 = time.perf_counter()

    def run(self):
        while True:
            for dp in self.app.datapaths.values():
                self.request_flow_stats(dp)
                self.request_switch_stats(dp)
            hub.sleep(self.interval)
