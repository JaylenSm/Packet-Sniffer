# Packet-Sniffer

This is a packet sniffer which leverages the socket library available in the standard Python library. This packet sniffer is designed to operate on Linux operating systems, if you try to operate this on other systems you may face issues similar to mine. I developed this tool in a WSL environment and as Windows utilizes isolation principles for security, the virtualized interface does not have full interpretation of Ethernet packets, instead some fragments can be interpreted (possibly not accurately at all.). By default this tool does not utilize promiscuous/monitor, the dedicated networking interface of the user will have to be manually set to promiscuous mode (sudo ifconfig eth0 promisc). The default NIC ID used for this script is "eth0", if a different one should be used then the user will have to manually change the default interface in the tool's backend. 

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

## 📜 Table of Contents

- [Features](#Features)
- [Usage](#Usage)
- [Presentation](#Presentation)
- [Requirements](#Requirements)
- [Installation](#Installation)

# Features 

- Sniffing RAW traffic while automatically converting byte formats to hexadecimal.
- Sniffing TCP traffic, however, content bodies are not sniffed when sniffing for TCP traffic.
- Sniffing UDP traffic, however, like TCP traffic, content bodies are not sniffed when sniffing for UDP traffic.
- All of the sniffing capabilities were made with local machine traffic (outgoing, ingoing) in mind. And has not been tested with promiscuous/monitor mode, nor is suited for capturing verbose packets. Capturing RAW packets does capture some content, however, this is due to capturing RAW data involving the process of not expecting a certain type of data to be received.

# Usage 

The intended use of this tool is to be used for incoming and outgoing traffic of a local machine in a non-verbose manner. Which can be useful when needing to only focus on TCP/UDP headers or testing baselines for all incoming/outgoing RAW data.

# Presentation

For a presentation/demo of the project [CLICK ME](https://onedrive.live.com/:p:/g/personal/8D3E98D829540707/EaFIBRELXh9JvErrBB0qjT0BXtqbTNiD_4eelAuKZDkHoA?resid=8D3E98D829540707!s110548a15e0b491fbc4aeb041d2a8d3d&ithint=file%2Cpptx&e=pwUwL7&migratedtospo=true&redeem=aHR0cHM6Ly8xZHJ2Lm1zL3AvYy84ZDNlOThkODI5NTQwNzA3L0VhRklCUkVMWGg5SnZFcnJCQjBxalQwQlh0cWJUTmlEXzRlZWxBdUtaRGtIb0E_ZT1wd1V3TDc)

# Requirements

- Make sure you are using a system compatible with the tool. The tool is pretty much compatible with most modern systems where socket access is available to the user (Linux, Windows, MacOS).

- Make sure that the latest version of Python3 is installed and utilized for the best performance.

- For the best experience it is recommended to use a Linux OS, as even a virtualized Linux OS can cause interpretation issues of Ethernet packets based on the OS. Due to limitations of virtualized interfaces in various OS systems natively.

# Installation

- The dedicated backend and frontend files are to be downloaded respectively (In the "src" folder). If the interface name needs to be changed it will have to be changed in the backend file, represented by "(interface = "eth0")" in the "Packet_Sniffer" class. For the tool to function the dedicated frontend file is to be ran (python3 frontend_packet_sniffer). 
