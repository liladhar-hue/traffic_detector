# Network Traffic Detector

A simple Python-based network monitoring tool that detects suspicious activity in real time.

## Features

* Detects new devices in local subnet
* Identifies high traffic from a single IP
* Detects possible port scanning behavior

## Requirements

* Python 3
* Scapy

## Installation

```bash
pip install scapy
```

## Usage

```bash
sudo python3 traffic_detector.py
```

## Example Output

```
[NEW DEVICE] 192.168.1.5
[ALERT] 192.168.1.10 high traffic!
[ALERT] 192.168.1.10 possible port scan!
```

## Note

Run with root privileges for packet capture.

## Virtual Environment Setup (Recommended)

If the script does not work in your system environment, you can use a virtual environment:

### Create a virtual environment

```bash
python3 -m venv traffic-env
```

### Activate the environment

```bash
source traffic-env/bin/activate
```

### Install dependencies

```bash
pip install scapy
```

### Run the script

run the script according to your file path and when job is done so you can close it.
Keep Learning! :)
