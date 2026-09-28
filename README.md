# SDN Controller for DoS Detection and Mitigation

Academic project focused on **Software Defined Networking (SDN)** security. The system uses a **Ryu controller**, **OpenFlow 1.3**, **Mininet**, and **Open vSwitch** to monitor network traffic, identify anomalous traffic patterns, and apply mitigation rules.

## Overview

The project is organized around three main stages:

1. **Monitoring** – periodically collects per-flow and aggregate switch statistics.
2. **Decision making** – analyzes recent traffic measurements to identify suspicious behavior.
3. **Enforcement** – installs OpenFlow rules that can restrict traffic associated with detected sources.

A Mininet test environment is included to generate coordinated UDP traffic toward a destination host and evaluate the controller behavior in a controlled laboratory network.

## Main components

- `controller.py` – main Ryu OpenFlow 1.3 controller and learning-switch logic.
- `monitoring.py` – collection and storage of flow/switch traffic statistics.
- `decision_making.py` – traffic analysis and detection logic.
- `enforcement.py` – mitigation actions through OpenFlow rules.
- `admin.py` – command-line management of MAC-address whitelist/blacklist data.
- `topology_attack2.py` – Mininet topology and coordinated traffic-generation environment.
- `admin_lists.json` / `liste.json` – configuration/state used by the controller components.

## Technologies

- Python
- Ryu SDN Framework
- OpenFlow 1.3
- Mininet
- Open vSwitch
- NumPy
- iperf

## Architecture

```text
Mininet hosts
     |
Open vSwitch
     |
Ryu Controller
     |
     +--> Monitoring
     |       |
     |       v
     +--> Decision Making
     |       |
     |       v
     +--> Enforcement
             |
             v
       OpenFlow rules
```

## Test environment

The included Mininet topology defines multiple hosts and switches. Host `h3` is used as the destination in the traffic-generation scenario, while other hosts can generate coordinated UDP bursts through `iperf`.

The traffic generator is intended for **controlled laboratory use only**.

## Requirements

The project requires a Linux environment with:

- Python 3
- Ryu
- NumPy
- Mininet
- Open vSwitch
- iperf

> Mininet and Open vSwitch are normally installed through the operating system package manager rather than `pip`.

## Running the project

Start the Ryu controller from the project directory:

```bash
ryu-manager controller.py
```

In another terminal, start the Mininet topology with root privileges:

```bash
sudo python3 topology_attack2.py
```

The topology also exposes a local control server on `127.0.0.1:9999` that accepts `START`, `STOP`, and `STATUS` commands for the test traffic generator.

## Administrative lists

Run:

```bash
python3 admin.py
```

to inspect or update the MAC-address whitelist and blacklist stored in `admin_lists.json`.

## Disclaimer

This repository contains an academic networking-security project created for educational and experimental purposes. Traffic-generation and mitigation functionality should only be used in networks and laboratory environments where you have authorization.
