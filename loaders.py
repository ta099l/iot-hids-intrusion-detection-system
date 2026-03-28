
import json
from typing import Dict, List, Any

def load_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)

def load_ics_port_whitelist(path: str) -> Dict[int, List[str]]:
    data = load_json(path)
    return {int(k): v for k, v in data["ics_port_whitelist"].items()}

def load_inbound_src_spoofing(path: str) -> Dict[int, str]:
    data = load_json(path)
    return {int(k): v for k, v in data["inbound_src_spoofing"].items()}

def load_outbound_dst_blacklist(path: str) -> Dict[int, str]:
    data = load_json(path)
    return {int(k): v for k, v in data["outbound_dst_blacklist"].items()}

def load_outbound_src_privilege_abuse(path: str) -> Dict[int, str]:
    data = load_json(path)
    return {int(k): v for k, v in data["outbound_src_privilege_abuse"].items()}

def load_high_risk_ports(path: str) -> Dict[int, str]:
    data = load_json(path)
    return {int(k): v for k, v in data["inbound_dst_high_risk"].items()}
