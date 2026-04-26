# Network Traffic Detector

A simple Python-based network monitoring tool that detects suspicious activity in real time and saves logs automatically.

## Features

- Detects new devices in local subnet
- Identifies high traffic from a single IP
- Detects possible port scanning behavior
- **Saves logs automatically** with timestamps in `logs/` folder

## Requirements

- Python 3
- Scapy

## Installation

```bash
pip install scapy
```

## Virtual Environment Setup (Recommended)

```bash
# Create
python3 -m venv traffic-env

# Activate
source traffic-env/bin/activate

# Install
pip install scapy
```

## Usage

```bash
sudo python3 traffic_detector.py
```

## Example Output

Terminal aur `logs/detector_YYYY-MM-DD_HH-MM-SS.log` save in both.
Keep learning! :)
