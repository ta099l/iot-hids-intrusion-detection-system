
import time

from scapy.all import IP

import ioc_manager
import packet_capture
import packet_processor

def main():
    manager = ioc_manager.ioc_manager()
    print(f"Initial load done: {len(manager.malicious_ips['ips'])} IPs loaded")

    manager.auto_updater(interval_hours=(2))
    pcap = packet_capture.packet_capture()
    pcap.start_capture("wlp4s0")

    while True:
        try:
            if not pcap.packet_queue.empty():
                packet = pcap.packet_queue.get()
                packet_processor.process_packet(packet, manager.malicious_ips)
            else:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] Stopping IDS...")
            pcap.stop()
            break
if __name__ == "__main__":
    main()
