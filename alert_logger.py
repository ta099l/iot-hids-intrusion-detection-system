#IMPORTANT NOTE: Dear professor Malik Alessa, this code was initially generated with the assistance of an AI tool and later reviewed, refactored, and adapted by me.

import json
import os
import time
from typing import List, Dict, Any


alert_file_path = "ids_alerts.json"


# In-memory cache to store the last timestamp an alert key was logged.
alert_cooldown_cache: Dict[str, float] = {}

alert_cooldown_seconds = 60


def _create_alert_key(alert_data: Dict[str, Any]) -> str:
    
    
    key_fields = (
        alert_data["source_ip"],
        alert_data["destination_ip"],
        str(alert_data["source_port"]),
        str(alert_data["destination_port"]),
        alert_data["direction"],
        
        tuple(sorted(alert_data["reasons"]))
    )
    
    return str(hash(key_fields))




def load_alerts() -> List[Dict[str, Any]]:

    if not os.path.exists(alert_file_path):
        return []
    try:
        with open(alert_file_path, 'r') as f:
            # Load the entire list of alerts
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError, IOError):
        # Handle cases where the file is empty, corrupted, or cannot be read
        print(f"[!] Warning: Could not load or parse {alert_file_path}. Starting with an empty alert list.")
        return []


def save_alerts(alerts: List[Dict[str, Any]]):
    
    try:
        with open(alert_file_path, 'w') as f:
            
            json.dump(alerts, f, indent=4)
    except IOError as e:
        print(f"[!] Error saving alerts to {alert_file_path}: {e}")


def log_alert(alert_data: Dict[str, Any]):


    global alert_cooldown_cache, alert_cooldown_seconds
    now = time.time()

    # 1. Generate unique key for this alert flow
    alert_key = _create_alert_key(alert_data)

    # 2. Check de-duplication cache
    last_alert_time = alert_cooldown_cache.get(alert_key, 0)

    if (now - last_alert_time) < alert_cooldown_seconds:
        # Alert is within the cooldown period suppress logging to file
        return

        # 3. Update the cache with the new time (only if we are about to log it)
    alert_cooldown_cache[alert_key] = now

    # 4. If outside the cooldown proceed with logging
    alerts = load_alerts()
    alerts.append(alert_data)
    save_alerts(alerts)
