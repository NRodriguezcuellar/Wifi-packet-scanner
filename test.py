from scapy.layers.dot11 import *
import time
import hashlib
from datetime import datetime
import requests


def signal_strength(pkt):
    try:
        extra = pkt.notdecoded
        rssi = -(256 - ord(extra[-4:-3]))
        return str(rssi)
    except rssi == -100:
        return 'out of reach'


def hash_mac(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


class Gateway:
    def __init__(self):
        self.cache = []

    def send_update(self):
        print(12312)
        while True:
            print('sending update')
            print(self.cache)
            api_key = "f015a18b3f8e051eb802ea5e459b67bbaec460f3f4bfacb6d0ff45b1afa1bd47"
            url = "http://127.0.0.1:8000/update_macs"
            headers = {"Authorization": f"Bearer {api_key}"}
            payload = {
                "data": self.cache,
                "time": datetime.now().isoformat(),
            }
            r = requests.post(url, headers=headers, json=payload)
            self.cache = []
            assert r.ok
            time.sleep(1)


def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return

    if pkt.type == 0 and pkt.subtype == 4:  # subtype used to be 8 (APs) but is now 4 (Probe Requests)
        curmac = pkt.addr2
        curmac = curmac.upper()  # Assign variable to packet mac and make it uppercase
        strength = signal_strength(pkt)
        GATEWAY.cache.append({'hash': hash_mac(curmac), 'strength': strength})

        if curmac:
            print(
                f"\033[95m Device MAC:{hash_mac(curmac)}  with SSID: {pkt.info} \033[92m  WiFi signal strength {strength} \033[92m \033[0m")


def main():
    # print(f" \n  \033[93m  Wifi Scanner Initialized  \033[0m  \n")
    # t = threading.Thread(target=GATEWAY.send_update())
    # t.start()
    sniff(iface='wlp2s0mon', prn=handle_packet)  # start sniffing
    # t.join()


if __name__ == '__main__':
    GATEWAY = Gateway()
    main()
