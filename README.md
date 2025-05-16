# Packet-Sniffer

This is a packet sniffer which leverages the socket library available in the standard Python library. This packet sniffer is designed to operate on Linux operating systems, if you try to operate this on other systems you may face issues similar to mine. I developed this tool in a WSL environment and as Windows utilizes isolation principles for security, the virtualized interface does not have full interpretation of Ethernet packets, instead some fragments can be interpreted (possibly not accurately at all.). By default this tool does not utilize promiscuous/monitor, the dedicated networking interface of the user will have to be manually set to promiscuous mode (sudo ifconfig eth0 promisc). The default NIC ID used for this script is "eth0", if a different one should be used then the user will have to manually change the default interface in the tool's backend. 


