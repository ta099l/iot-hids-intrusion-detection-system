
import requests


# This is used to fetch the bad ips from these two lists i found on github
class ioc_fetcher:

    @staticmethod
    def fetch_ipsum():
        url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # throws an exception for 5xx and 4xx errors
            ips = set()  # a set to save unique ip inside it.
            for line in response.text.splitlines():
                if line and not line.startswith("#"):
                    parts = line.split()
                    ips.add(parts[0].strip())
            return ips

        except requests.RequestException as e:
            print(f"[!] Failed to fetch IPsum list: {e}")
            return set()

    @staticmethod
    def fetch_bitwire():
        url = "https://raw.githubusercontent.com/bitwire-it/ipblocklist/refs/heads/main/ip-list.txt"

        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()

            ips = set()
            for line in response.text.splitlines():
                if line and not line.startswith("#"):
                    ips.add(line.strip())
            return ips
        except requests.RequestException as e:
            print(f"[!] Failed to fetch bitwire list: {e}")
            return set()

    @staticmethod
    def combine_ioc_sets():
        ipsum_ips = ioc_fetcher.fetch_ipsum()
        bitwire_ips = ioc_fetcher.fetch_bitwire()
        combined = ipsum_ips.union(bitwire_ips)
        return combined
