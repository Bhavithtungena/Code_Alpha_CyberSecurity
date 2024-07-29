#Simple Basic Network Sniffer

from scapy.all import sniff # type: ignore

capture=sniff(count=5)
capture.summary()