
import queue
import threading

from scapy.all import sniff, IP


class packet_capture:
    def __init__(self):
        self.packet_queue = queue.Queue(maxsize=1000)  # to store captured packets
        # queue.Queue() is part of Python’s thread-safe queue system — it’s used to safely pass data between threads. If we don't use it both threads could try to read/write the same data at the same time.
        self.stop_capture = threading.Event()  # Class to implement event object

    # to control when the packet capture should stop

    def packet_callback(self, packet):
        if IP in packet:
            try:
                self.packet_queue.put(packet, timeout=0.1)
            except queue.Full:
                pass

    # an exception in case the queue is full. it drops the packets

    def start_capture(self, interface="eth0"):
        def capture_thread():
            try:
                sniff(
                    iface=interface,
                    filter="ip",
                    prn=self.packet_callback,
                    store=0,
                    stop_filter=lambda _: self.stop_capture.is_set()
                )
            except PermissionError:
                print("[!] Permission denied! Run with sudo.")
            except KeyboardInterrupt:
                print("\n[!] Capture stopped by user.")
            except Exception as e:
                print(f"[!] Sniffing error: {e}")
            # lambda is a one line function to use instead opf keep writing functions. this _ means ignore this value which is the arguements. here we check if stop_capture is false or true should we keep capturing or should we stop capturing.

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()


if __name__ == "__main__":

    pcap = packet_capture()
    pcap.start_capture("wlp4s0")

    import time

    print("Sniffing packets for 10 seconds...")
    time.sleep(10)

    pcap.stop()
    print(f"Captured {pcap.packet_queue.qsize()} packets.")

    while not pcap.packet_queue.empty():
        packet = pcap.packet_queue.get()
        print(packet.summary())
