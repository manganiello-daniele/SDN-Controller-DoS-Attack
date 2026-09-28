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

import threading
import time
import json
import numpy as np
from collections import deque
from monitoring import monitoring_thread
from enforcement import Enforcement_thread
from statistics import median


class DecisionMaking_thread(threading.Thread):
    def __init__(self, monitoring, enforcement, interval=10, threshold=700000):
        super().__init__(daemon=True)
        self.monitoring = monitoring
        self.enforcement = enforcement
        self.interval = interval

        self.stats = {}
        self.switch = {}
        self.alarm_flow = {}
        self.flow_history = {}

        self.blocklist = []
        self.blocklist_perm = []
        self.whitelist = []
        self.blacklist = []

        self.slowlist = []
        self.slow_alarm = {}
        self.slow_duration = 30
        self.soglia_rallenta_factor = 0.8
        self.slow_repeated = {}

        self.alarm_burst_mac = {}
        self.safe_counter = {}
        self.var_alarm_counter = {}
        self.var_slowlist = {}
        self.slow_safe_counter = {}

        self.threshold = threshold
        self.fallback_threshold = threshold
        self.max_vr = 20_000_000_000
        self.max_sw_vr = 50_000_000_000
        self.history_window = 5
        self.min_samples = 3
        self.global_factor = 1.0

    def leggi_lista(self, lista, path, tipo):
        try:
            with open(path, "r") as f:
                data = json.load(f)
            lista.clear()
            lista.extend(data.get(tipo, []))
        except Exception:
            pass

    def aggiorna_da_blacklist_file(self):
        try:
            with open("admin_lists.json", "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = {}

        blacklist_file = data.get("blacklist", [])
        whitelist_file = data.get("whitelist", [])

        for mac in blacklist_file:
            if mac not in self.blocklist_perm:
                self.blocklist_perm.append(mac)
                print(f"[File] MAC {mac} aggiunto a blocklist permanente")

        for mac in whitelist_file:
            if mac not in self.whitelist:
                self.whitelist.append(mac)
                print(f"[File] MAC {mac} aggiunto a whitelist")

        data["blacklist"] = []
        data["whitelist"] = []

        with open("admin_lists.json", "w") as f:
            json.dump(data, f, indent=4)

    def varianza(self, values):
        return np.var(values)

    def monitor_flow(self, id_switch):
        max_vr_high = self.max_vr
        max_vr_low = self.max_vr * 0.5

        for mac in self.monitoring.flow_store[id_switch]:
            valori = list(self.monitoring.flow_store[id_switch][mac].values())
            if not valori:
                continue

            if mac in self.whitelist or mac in self.blocklist_perm:
                continue

            varianza = self.varianza(valori)
            key = (id_switch, mac)
            self.var_alarm_counter[key] = self.var_alarm_counter.get(key, 0)

            if varianza > max_vr_high:
                self.var_alarm_counter[key] += 1
            elif varianza < max_vr_low:
                self.var_alarm_counter[key] = max(0, self.var_alarm_counter[key] - 1)

            slow_threshold = 2
            block_threshold = 4

            if (
                self.var_alarm_counter[key] >= slow_threshold
                and self.var_alarm_counter[key] < block_threshold
                and mac not in self.var_slowlist
                and mac not in self.blocklist
            ):
                print(f"[Varianza] Mitigazione per {mac} (varianza alta ripetuta)")
                try:
                    self.enforcement.slow(mac)
                except Exception as e:
                    print(f"[monitor_flow] errore slow {mac}: {e}")
                self.var_slowlist[mac] = time.time()

            if (
                self.var_alarm_counter[key] >= block_threshold
                and mac not in self.blocklist
                and mac not in self.whitelist
            ):
                print(f" [Varianza] Blocco per {mac} (varianza costantemente alta)")
                try:
                    self.enforcement.block(mac, "blocklist")
                except Exception as e:
                    print(f"[monitor_flow] errore block {mac}: {e}")
                self.blocklist.append(mac)
                if mac in self.var_slowlist:
                    try:
                        self.enforcement.unslow(mac)
                    except Exception:
                        pass
                    del self.var_slowlist[mac]

            self.slow_safe_counter[mac] = self.slow_safe_counter.get(mac, 0)

            if self.var_alarm_counter[key] < 2:
                self.slow_safe_counter[mac] += 1
            else:
                self.slow_safe_counter[mac] = 0

            if (
                mac in self.var_slowlist
                and time.time() - self.var_slowlist[mac] > self.slow_duration
                and varianza < max_vr_low
                and self.slow_safe_counter[mac] >= 3
            ):
                print(f" [Varianza] Fine mitigazione per {mac}")
                try:
                    self.enforcement.unslow(mac)
                except Exception as e:
                    print(f"[monitor_flow] errore unslow {mac}: {e}")
                del self.var_slowlist[mac]
                self.var_alarm_counter[key] = 0

        self.slow_safe_counter = {}

    def run(self):
        while True:
            print("\n================= Decision Making Cycle =================")

            self.stats = self.monitoring.stats
            self.switch = self.monitoring.switch_store
            self.alarm_flow = self.monitoring.alarm_flow

            self.aggiorna_da_blacklist_file()

            all_values = [
                v
                for sw in self.stats.values()
                for mac, v in sw.items()
                if mac not in self.blocklist and mac not in self.blocklist_perm and mac not in self.whitelist
            ]

            if len(all_values) > 0:
                med = median(all_values)
                abs_dev = [abs(x - med) for x in all_values]
                MAD = median(abs_dev)
                scaled_MAD = MAD * 1.4826
                threshold_globale = med + self.global_factor * scaled_MAD
                threshold_globale = max(threshold_globale, self.fallback_threshold)
            else:
                threshold_globale = self.fallback_threshold

            print(f"Soglia globale adattiva: {threshold_globale:.2f}")

            for id_switch in self.switch:
                valori = list(self.switch[id_switch].values())
                sw_var = self.varianza(valori) if len(valori) == 10 else 0

                if len(valori) == 10 and sw_var > self.max_sw_vr:
                    self.monitor_flow(id_switch)
                    continue

                host_da_controllare = False

                for mac in self.var_slowlist:
                    host_da_controllare = True
                    break

                if not host_da_controllare:
                    for mac in self.monitoring.flow_store.get(id_switch, {}):
                        if self.var_alarm_counter.get((id_switch, mac), 0) > 0:
                            host_da_controllare = True
                            break

                if host_da_controllare:
                    if id_switch in self.monitoring.flow_store:
                        self.monitor_flow(id_switch)

            for id_switch in self.stats:
                for mac, valore_corrente in self.stats[id_switch].items():
                    if mac in self.blocklist_perm or mac in self.whitelist:
                        continue

                    key = (id_switch, mac)
                    hist = self.flow_history.get(key, [])
                    hist.append(valore_corrente)
                    if len(hist) > self.history_window:
                        hist.pop(0)
                    self.flow_history[key] = hist

                    if len(hist) >= self.min_samples:
                        mean = np.mean(hist)
                        std = np.std(hist)
                        soglia_host = mean + 2 * std
                    else:
                        soglia_host = self.fallback_threshold

                    if soglia_host < self.fallback_threshold:
                        soglia_effettiva = max(soglia_host, threshold_globale)
                    else:
                        soglia_effettiva = threshold_globale

                    soglia_rallenta = soglia_effettiva * self.soglia_rallenta_factor
                    self.alarm_flow[key] = self.alarm_flow.get(key, 0)

                    if valore_corrente > soglia_effettiva:
                        self.alarm_flow[key] += 2
                    elif valore_corrente > soglia_rallenta:
                        self.alarm_flow[key] += 1
                    else:
                        self.alarm_flow[key] = max(0, self.alarm_flow[key] - 1)

                    slow_threshold = 2
                    block_threshold = 4

                    if (
                        self.alarm_flow[key] >= slow_threshold
                        and self.alarm_flow[key] < block_threshold
                        and mac not in self.slowlist
                        and mac not in self.blocklist
                        and mac not in self.whitelist
                    ):
                        print(f"[Mitigazione] {mac} supera soglia {self.alarm_flow[key]} volte → rallento.")
                        try:
                            self.enforcement.slow(mac)
                        except Exception as e:
                            print(f"[run] errore slow {mac}: {e}")
                        self.slowlist.append(mac)
                        self.slow_alarm[mac] = time.time()

                    if (
                        self.alarm_flow[key] >= block_threshold
                        and mac not in self.blocklist
                        and mac not in self.whitelist
                    ):
                        print(f"[Blocco definitivo] {mac} (superata soglia {self.alarm_flow[key]} volte)")
                        self.enforcement.block(mac, "blocklist")
                        if mac in self.slowlist:
                            self.enforcement.unslow(mac)
                            self.slowlist.remove(mac)
                        self.blocklist.append(mac)
                        self.alarm_flow[key] = 0

                    if mac in self.slowlist:
                        self.slow_safe_counter[mac] = self.slow_safe_counter.get(mac, 0)

                        if valore_corrente < soglia_rallenta:
                            self.slow_safe_counter[mac] += 1
                        else:
                            self.slow_safe_counter[mac] = 0

                        if self.slow_safe_counter[mac] >= 8:
                            print(f"[Fine mitigazione] {mac} torna stabile in modo consistente")
                            try:
                                self.enforcement.unslow(mac)
                            except Exception as e:
                                print(f"[run] errore unslow {mac}: {e}")
                            self.slowlist.remove(mac)
                            self.slow_safe_counter[mac] = 0
                            self.alarm_flow[key] = 0

            time.sleep(self.interval)
