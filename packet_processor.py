
import json
import os
import socket
import time
from typing import Literal

import requests
from dotenv import load_dotenv
from scapy.all import IP, TCP, UDP

import alert_logger
from cache_manager import abuse_cache, save_cache
from loaders import (
    load_ics_port_whitelist,
    load_inbound_src_spoofing,
    load_outbound_dst_blacklist,
    load_outbound_src_privilege_abuse,
    load_high_risk_ports
)


abuseipdb_rate_limit = 1000
abuseipdb_request_count = 0
abuseipdb_limit_reached_printed = False  # Flag to print the warning only once

alert_threshold = 1
config_path = "config/ioc_rules.json"

ics_port_whitelist = load_ics_port_whitelist(config_path)
inbound_spoofing = load_inbound_src_spoofing(config_path)
outbound_blacklist = load_outbound_dst_blacklist(config_path)
outbound_priv_abuse = load_outbound_src_privilege_abuse(config_path)
high_risk_ports = load_high_risk_ports(config_path)

DEFAULT_CACHE_ENTRY = {
    "malicious": False,
    "last_alert": 0,
    "source": None
}




def get_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()



def get_direction(src_ip, my_ip):
    return "OUTBOUND" if src_ip == my_ip else "INBOUND"




def load_cache(path="abuse_cache.json"):
    if not os.path.exists(path):
        return {}

    with open(path, "r") as f:
        return json.load(f)




def extract_features(pkt):
    if IP not in pkt:
        return "0.0.0.0", "0.0.0.0", -1, -1, "UNKNOWN"
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    # Use -1 as the value for ports to indicate "No Transport Layer"
    src_port = -1
    dst_port = -1
    connection_state: ConnectionState = "UNKNOWN"
    # print("I'm in extract features func.")

    if TCP in pkt:
        # print("TCP was found in the packet")
        tcp_layer = pkt[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        flags = tcp_layer.flags

        connection_state = determine_connection_state(
            is_syn_set=bool(flags & 0x02),
            is_ack_set=bool(flags & 0x10),
            is_fin_set=bool(flags & 0x01),
            is_rst_set=bool(flags & 0x04)
        )
    elif UDP in pkt:
        # print("In UDO")
        udp_layer = pkt[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        # connection_state remains UNKNOWN for UDP 

    
    return src_ip, dst_ip, src_port, dst_port, connection_state


# src_ip, dst_ip, src_port, dst_port, connection_state = extract_features(pkt)
ConnectionState = Literal["NEW", "ESTABLISHED", "FINISHING", "UNKNOWN"]


def determine_connection_state(
    #print("I'm in determine_connection_state")
        is_syn_set: bool,
        is_ack_set: bool,
        is_fin_set: bool = False,
        is_rst_set: bool = False
) -> ConnectionState:

    if is_rst_set or is_fin_set:
        return "FINISHING"
    if is_syn_set and not is_ack_set:
        return "NEW"
    if is_ack_set:
        return "ESTABLISHED"
    return "UNKNOWN"




def process_packet(pkt, malicious_ips):
    

    packet_score = 0
    packet_reasons = []
    # print("I'm in process packet")
   
    src_ip, dst_ip, src_port, dst_port, connection_state = extract_features(pkt)

    if src_ip == "0.0.0.0":
        return {
            "score": 0,
            "reasons": [],
            "src_ip": None,
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "state": "UNKNOWN",
            "direction": "UNKNOWN"
        }

    my_ip = get_ipv4()

    direction = get_direction(src_ip, my_ip)

    # IP Reputation Check (Source for INBOUND, Destination for OUTBOUND)
    # this logic ensures that 'my_ip' is never the subject of the reputation check.
    ip_to_check = src_ip if direction == "INBOUND" else dst_ip

    ip_score, ip_reasons = check_ip_reputation(ip_to_check, malicious_ips["ips"])
    packet_score += ip_score
    packet_reasons.extend(ip_reasons)

    # Port Checks (only if a transport layer exists)
    if src_port != -1:
        port_score = 0
        port_reasons = []

        if direction == "INBOUND":
            port_score, port_reasons = check_ports_inbound(src_ip, dst_port, src_port, connection_state)

        elif direction == "OUTBOUND":
            port_score, port_reasons = check_ports_outbound(dst_ip, dst_port, src_port)

        packet_score += port_score
        packet_reasons.extend(port_reasons)

    # Update cache score
    cache_entry = abuse_cache.setdefault(ip_to_check, dict(DEFAULT_CACHE_ENTRY))
    cache_entry["score"] = packet_score

    # ---- ALERT ----
    if packet_score >= alert_threshold and packet_reasons:
        alert_data = {
            "timestamp": time.time(),
            "score": packet_score,
            "direction": direction,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "protected_device_ip": my_ip,
            # Use '?' if ports were not determined (e.g., ICMP/Other)
            "source_port": src_port if src_port is not None else '?',
            "destination_port": dst_port if dst_port is not None else '?',
            "connection_state": connection_state,
            "reasons": packet_reasons
        }

        # Log the structured alert to the JSON file
        alert_logger.log_alert(alert_data)
        # ------------------------------------------------------------
    if packet_score >= alert_threshold and packet_reasons:
        print("\n=========================================== IDS ALERT ==========================================")
        print(f"Score reached: {packet_score}")
        print(f"Protected Device: {my_ip}")

        display_src_port = src_port if src_port != -1 else 'N/A'
        display_dst_port = dst_port if dst_port != -1 else 'N/A'

        print(
            f"Flow: {src_ip}:{display_src_port} -> {dst_ip}:{display_dst_port} | State: {connection_state} | Direction: {direction}")
        print("Reasons:")
        for r in packet_reasons:
            print(" •", r)
        print("===============================================================================================\n")

    # the return is not neccessary but using it to test this function and i hope it works cuz i'm tired and i want to sleeeeeeeeeep
    return {
        "score": packet_score,
        "reasons": packet_reasons,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "state": connection_state,
        "direction": direction
    }


##################################IP_CHECK##############################################################################

alert_window = 600  # 10 minutes in seconds
load_dotenv("api.env")  # loading environment variables from .env file




def check_ip_reputation(
        ip_to_check: str,
        malicious_ips
) -> tuple[int, list[str]]:

    score = 0
    reasons = []
    now = time.time()

   
    cache_entry = abuse_cache.setdefault(ip_to_check, dict(DEFAULT_CACHE_ENTRY))

    
    if cache_entry["malicious"] is True:
        if now - cache_entry["last_alert"] > alert_window:
            score += 70
            reasons.append(f"[!!!] CRITICAL: Cached malicious IP ({ip_to_check}) - {cache_entry['source']}")
            cache_entry["last_alert"] = now
        else:
            reasons.append(f"[INFO] Malicious IP ({ip_to_check}) hit suppressed by rate limit.")
        return score, reasons

    
    if ip_to_check in malicious_ips:
        cache_entry.update({"malicious": True, "source": "LOCAL_IOC", "last_alert": now})
        score += 70
        reasons.append(f"[!!!] CRITICAL: IP matched local IOC blacklist ({ip_to_check})")
        return score, reasons

   
    if query_abuseipdb(ip_to_check):
        cache_entry.update({"malicious": True, "source": "ABUSEIPDB", "last_alert": now})
        score += 70
        reasons.append(f"[!!!] CRITICAL: IP flagged malicious via AbuseIPDB ({ip_to_check})")
        return score, reasons

    cache_entry["malicious"] = False
    return score, reasons


###################################################PORT_CHECKING####################################
def check_ports_inbound(
        src_ip: str,
        dst_port: int,
        src_port: int,
        connection_state: ConnectionState
) -> tuple[int, list[str]]:
    score = 0
    reasons = []

    # CRITICAL ICS Whitelist (Unauthorized Access)
    if dst_port in ics_port_whitelist:
        if not check_ip_in_whitelist(src_ip, dst_port):
            score += 100  # Highest score - ICS breach
            reasons.append(f"[!!!] CRITICAL: Unauthorized access on ICS port {dst_port} from {src_ip}.")
            return score, reasons
        reasons.append(f"[CLEAN] ICS Whitelist Match: Authorized traffic on port {dst_port}.")
        return score, reasons

    # Destination Port Blacklist (Exploitation/Backdoors)
    if dst_port in high_risk_ports:
        score += 50
        reasons.append(f"[!!!] High-Risk Destination Port: {dst_port} → {high_risk_ports[dst_port]} from {src_ip}. ")

    # Source Port Spoofing (State Aware)
    # Only flag this if it's a NEW connection attempt (i.e., not a legitimate reply)
    if src_port in inbound_spoofing and connection_state == 'NEW':
        score += 40
        reasons.append(f"[!!!] Spoofing Attempt: Unsolicited traffic from privileged source port {src_port}.")

    return score, reasons


def check_ports_outbound(
        dst_ip: str,
        dst_port: int,
        src_port: int,
        #connection_state: ConnectionState       #I might need it later who knows?
) -> tuple[int, list[str]]:
    
    score = 0
    reasons = []

    # Destination Blacklist Check (C2 Detection)
    if dst_port in outbound_blacklist:
        score += 70  
        reasons.append(f"[!!!] CRITICAL: Attempt to connect to Blacklisted C2 Port {dst_port}. The destination IP is {dst_ip}.")

    # Source Port Privilege Abuse Check
    # Flags the device using a privileged source port (<1024) to connect out.
    if src_port in outbound_priv_abuse:
        score += 50
        reasons.append(f"[!!!] Privilege Abuse: Outbound connection using privileged source port {src_port}. The destination IP is {dst_ip}.")

    return score, reasons


####################################################################################################################API#########################################

def query_abuseipdb(ip):
    global abuseipdb_request_count, abuseipdb_limit_reached_printed, abuseipdb_rate_limit

    
    if abuseipdb_request_count >= abuseipdb_rate_limit:
        if not abuseipdb_limit_reached_printed:
            
            print(f"[!] WARNING: AbuseIPDB API rate limit ({abuseipdb_rate_limit}) reached. Skipping future API calls.")
            abuseipdb_limit_reached_printed = True
        return False
    # end of the rate checking

    # Using snake_case for the local variable holding the key
    api_key = os.getenv("ABUSEIPDB_KEY")
    if not api_key:
        print("[!] ERROR: AbuseIPDB_KEY environment variable not set.")
        return False

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    # Using the snake_case api_key here
    headers = {"Key": api_key, "Accept": "application/json"}

    try:
        
        abuseipdb_request_count += 1

        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        score = data["data"]["abuseConfidenceScore"]
        is_malicious = score >= 70

       
        abuse_cache[ip] = {
            "malicious": is_malicious,
            "last_alert": time.time(),
            "source": "ABUSEIPDB"  
        }
        save_cache(abuse_cache)

        return is_malicious


    except requests.RequestException as e:
        # Decrement on true HTTP error or request failure so the count is more accurate
        # but only if the error is NOT the 429 rate limit error which should be handled
        # by the global counter above on future calls.
        if '429 Client Error' not in str(e):
            abuseipdb_request_count -= 1
        print(f"[!] Error querying AbuseIPDB for {ip}: {e}")
        return False


###############################################################################
def check_ip_in_whitelist(src_ip: str, dst_port: int) -> bool:
    
    if dst_port in ics_port_whitelist:
        return src_ip in ics_port_whitelist[dst_port]
    return False
