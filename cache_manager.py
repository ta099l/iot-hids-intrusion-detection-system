
import json
import os

cache_file = "abuse_cache.json"


def load_cache():
    try:
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print("[!] Warning: Cache file corrupted, starting fresh.")
        return {}

    except FileNotFoundError as e:
        print(f"[!] ERROR: {e}")
        return {}
    except PermissionError:
        print(f"[!] ERROR: Permission denied when reading {path}.")
        return {}

    except ValueError as e:
        print(f"[!] ERROR: {e}")
        return {}

    except Exception as e:
        print(f"[!] Unexpected error while loading IOC file: {e}")
        return {}


def save_cache(cache):
    try:
        with open(cache_file, "w") as f:
            json.dump(cache, f, indent=4)
    except Exception as e:
        print(f"[!] ERROR saving cache: {e}")


abuse_cache = load_cache()
alerted_ips = set()  # Tracks which IPs were already alerted
