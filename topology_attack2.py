#!/usr/bin/python3
import threading
import time
import socket
import socketserver
from mininet.log import setLogLevel, info
from mininet.topo import Topo
from mininet.net import Mininet, CLI
from mininet.node import OVSKernelSwitch, Host
from mininet.link import TCLink
from mininet.node import RemoteController #Controller

class Environment(object):

    def __init__(self):
        "Create a network."
        self.net = Mininet(controller=RemoteController, link=TCLink)
        info("*** Starting controller\n")
        c1 = self.net.addController('c1', controller=RemoteController)
        info("*** Adding hosts and switches\n")

        self.h1 = self.net.addHost('h1', mac='00:00:00:00:00:01', ip='10.0.0.1')
        self.h2 = self.net.addHost('h2', mac='00:00:00:00:00:02', ip='10.0.0.2')
        self.h3 = self.net.addHost('h3', mac='00:00:00:00:00:03', ip='10.0.0.3')
        self.h4 = self.net.addHost('h4', mac='00:00:00:00:00:04', ip='10.0.0.4')
        self.h5 = self.net.addHost('h5', mac='00:00:00:00:00:05', ip='10.0.0.5')
        self.h6 = self.net.addHost('h6', mac='00:00:00:00:00:06', ip='10.0.0.6')
        self.h7 = self.net.addHost('h7', mac='00:00:00:00:00:07', ip='10.0.0.7')
        self.h8 = self.net.addHost('h8', mac='00:00:00:00:00:08', ip='10.0.0.8')

        self.s1 = self.net.addSwitch('s1', cls=OVSKernelSwitch)
        self.s2 = self.net.addSwitch('s2', cls=OVSKernelSwitch)
        self.s3 = self.net.addSwitch('s3', cls=OVSKernelSwitch)
        self.s4 = self.net.addSwitch('s4', cls=OVSKernelSwitch)
        self.s5 = self.net.addSwitch('s5', cls=OVSKernelSwitch)
        self.s6 = self.net.addSwitch('s6', cls=OVSKernelSwitch)
        self.s7 = self.net.addSwitch('s7', cls=OVSKernelSwitch)
        self.s8 = self.net.addSwitch('s8', cls=OVSKernelSwitch)
        self.s9 = self.net.addSwitch('s9', cls=OVSKernelSwitch)

        info("*** Adding links\n")
        self.net.addLink(self.h1, self.s1, bw=10, delay='0.0025ms')
        self.s1_to_s3 = self.net.addLink(self.s1, self.s3, bw=6, delay='25ms')
        self.net.addLink(self.h2, self.s2, bw=6, delay='25ms')
        self.s2_to_s3 = self.net.addLink(self.s2, self.s3, bw=6, delay='25ms')
        self.s3_to_s4 = self.net.addLink(self.s3, self.s4, bw=6, delay='25ms')
        self.net.addLink(self.s4, self.h3, bw=10, delay='0.0025ms')
        self.net.addLink(self.h4, self.s5, bw=6, delay='25ms')
        self.net.addLink(self.s5, self.s3, bw=6, delay='25ms')
        self.net.addLink(self.h5, self.s6, bw=6, delay='25ms')
        self.net.addLink(self.s6, self.s3, bw=6, delay='25ms')
        self.net.addLink(self.h6, self.s7, bw=6, delay='25ms')
        self.net.addLink(self.s7, self.s4, bw=6, delay='25ms')
        self.net.addLink(self.h7, self.s8, bw=6, delay='25ms')
        self.net.addLink(self.s8, self.s2, bw=6, delay='25ms')
        self.net.addLink(self.h8, self.s9, bw=6, delay='25ms')
        self.net.addLink(self.s9, self.s1, bw=6, delay='25ms')

        self.attack_threads = []
        self.attack_lock = threading.Lock()
        self.attack_running = False

    def start_network(self):
        info("*** Starting network\n")
        self.net.build()
        self.net.start()

        dst_host = self.net.get('h3')
        dst_host.cmd('pkill -f "iperf -s -p 5201" || true')
        dst_host.cmd('iperf -s -p 5201 -u > /tmp/iperf_server_%s.log 2>&1 &' % dst_host.name)
        time.sleep(0.2)

    def launch_coordinated_bursts(self,
                                  srcs=('h1','h2'),
                                  dst='h3',
                                  rounds=8,
                                  per_src_bw='3.5M',
                                  proto='udp',
                                  duration=3,
                                  interdelay=3,
                                  jitter=0.2):
        """
        Lancia diversi round di burst coordinati (uso interno / background).
        Parametri come prima.
        """
        dst_host = self.net.get(dst)
        src_hosts = [self.net.get(s) for s in srcs]

        for r in range(rounds):
            with self.attack_lock:
                if not self.attack_running:
                    info("*** Attack stopped by request\n")
                    return

            info("*** Round %d: each source sending %s for %ds (jitter=%s)\n" % (r+1, per_src_bw, duration, jitter))
            for idx, sh in enumerate(src_hosts):
                stagger = jitter * idx
                time.sleep(stagger)
                sh.cmd('iperf -c %s -p 5201 -u -b %s -t %d > /tmp/iperf_client_%s_round%d.log 2>&1 &' %
                       (dst_host.IP(), per_src_bw, duration, sh.name, r+1))

            time.sleep(duration + interdelay)

            try:
                info(self.net.get('s3').cmd('ovs-ofctl -O OpenFlow13 dump-flows s3 || ovs-ofctl dump-flows s3') + '\n')
            except Exception:
                pass

        info("*** All bursts finished.\n")

    def start_attack_background(self, **kwargs):
        with self.attack_lock:
            if self.attack_running:
                return False, "Attack already running"
            self.attack_running = True

        t = threading.Thread(target=self._attack_thread_target, kwargs=kwargs, daemon=True)
        t.start()
        with self.attack_lock:
            self.attack_threads.append(t)
        return True, "Attack started"

    def _attack_thread_target(self, **kwargs):
        try:
            self.launch_coordinated_bursts(**kwargs)
        finally:
            with self.attack_lock:
                self.attack_running = False

    def stop_attacks(self):
        with self.attack_lock:
            if not self.attack_running:
                return False, "No attack running"
            self.attack_running = False

        for hname in ('h1','h2','h4','h5','h6','h7','h8'):
            try:
                host = self.net.get(hname)
                host.cmd('pkill -f iperf || true')
            except Exception:
                pass
        return True, "Attack stop requested"

    def start_control_server(self, host='127.0.0.1', port=9999):
        env = self

        class ControlTCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                data = self.request.recv(1024).strip().decode('utf-8')
                if not data:
                    return
                parts = data.split()
                cmd = parts[0].upper()
                if cmd == 'START':
                    try:
                        srcs = parts[1].split(',') if len(parts) > 1 else ('h1','h2')
                        dst = parts[2] if len(parts) > 2 else 'h3'
                        rounds = int(parts[3]) if len(parts) > 3 else 50
                        per_src_bw = parts[4] if len(parts) > 4 else '3.5M'
                        duration = int(parts[5]) if len(parts) > 5 else 3
                        interdelay = int(parts[6]) if len(parts) > 6 else 3
                        jitter = float(parts[7]) if len(parts) > 7 else 0.2
                    except Exception as e:
                        resp = "ERROR: bad START args: %s\n" % e
                        self.request.sendall(resp.encode())
                        return

                    ok, msg = env.start_attack_background(
                        srcs=tuple(srcs),
                        dst=dst,
                        rounds=rounds,
                        per_src_bw=per_src_bw,
                        duration=duration,
                        interdelay=interdelay,
                        jitter=jitter
                    )
                    resp = ("OK: " if ok else "ERROR: ") + msg + "\n"
                    self.request.sendall(resp.encode())
                elif cmd == 'STOP':
                    ok, msg = env.stop_attacks()
                    resp = ("OK: " if ok else "ERROR: ") + msg + "\n"
                    self.request.sendall(resp.encode())
                elif cmd == 'STATUS':
                    with env.attack_lock:
                        running = env.attack_running
                    resp = "RUNNING\n" if running else "IDLE\n"
                    self.request.sendall(resp.encode())
                else:
                    self.request.sendall(b"ERROR: unknown command\n")

        server = socketserver.ThreadingTCPServer((host, port), ControlTCPHandler)
        server.daemon_threads = True
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        info("*** Control server started on %s:%d (use netcat to send START/STOP/STATUS)\n" % (host, port))
        return server

if __name__ == '__main__':
    setLogLevel('info')
    info('starting the environment\n')
    env = Environment()
    env.start_network()
    server = env.start_control_server(host='127.0.0.1', port=9999)

    info("*** Running CLI (you can inspect flows, logs, cpu, etc.)\n")
    CLI(env.net)

    info("*** Stopping network and control server\n")
    try:
        server.shutdown()
    except Exception:
        pass
    env.net.stop()
