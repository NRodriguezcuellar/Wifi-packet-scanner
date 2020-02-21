import hashlib
from datetime import datetime

import requests
from scapy.layers.dot11 import Dot11ProbeReq, sniff, RadioTap

output = []


def send_update():
    print("sending update")
    global output
    api_key = "f015a18b3f8e051eb802ea5e459b67bbaec460f3f4bfacb6d0ff45b1afa1bd47"
    url = "http://194.88.106.34/update_macs"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {"data": output, "time": datetime.now().isoformat()}
    r = requests.post(url, headers=headers, json=payload)
    print(f"sent: {r.status_code}")
    assert r.ok  # 4debug, add try except for timeout autism in prod
    output = []


def hash_mac(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return

    if pkt.type == 0 and pkt.subtype == 4:  # filters out beacon requests
        unhashed_mac = pkt.addr2.upper()
        signal_strength = pkt.getlayer(RadioTap).dBm_AntSignal
        mac = hash_mac(unhashed_mac)

        debug = f"\033[95m Device MAC:{unhashed_mac} - WiFi signal strength {signal_strength} \033[92m \033[0m"
        print(debug)
        output.append({"hash": mac, "strength": signal_strength})


def main():
    print(f" \n  \033[93m  Wifi Scanner Initialized  \033[0m  \n")
    while True:
        sniff(iface="wlan1mon", prn=handle_packet, timeout=60)  # start sniffing
        send_update()


if __name__ == "__main__":
    main()
