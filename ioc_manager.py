
import threading
import time

import ioc_fetcher


class ioc_manager:

    def __init__(self):
        self.malicious_ips = {"ips": ioc_fetcher.ioc_fetcher.combine_ioc_sets()}

    def auto_update(self, interval_hours=2):
        while True:
            new_list = ioc_fetcher.ioc_fetcher.combine_ioc_sets()
            self.malicious_ips["ips"] = new_list
            time.sleep(interval_hours * 3600)

    def auto_updater(self, interval_hours=2):
        thread = threading.Thread(target=self.auto_update, args=(interval_hours,), daemon=True)
        thread.start()


if __name__ == "__main__":
    manager = ioc_manager()
    print("In main")
    manager.auto_updater(interval_hours=(10 / 3600))  # 10 seconds
    print("Done updating")
