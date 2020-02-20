import hashlib
from datetime import datetime

import requests
from scapy.layers.dot11 import Dot11ProbeReq, sniff

output = []


def send_update():
    print("sending update")
    global output
    api_key = "f015a18b3f8e051eb802ea5e459b67bbaec460f3f4bfacb6d0ff45b1afa1bd47"
    url = "http://127.0.0.1:8000/update_macs"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {"data": output, "time": datetime.now().isoformat()}
    r = requests.post(url, headers=headers, json=payload)
    print(f"sent: {r.status_code}")
    assert r.ok  # 4debug, add try except for timeout autism in prod
    output = []


def hash_mac(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def get_signal_strength(pkt):
    extra = pkt.notdecoded
    rssi = -(256 - ord(extra[-4:-3]))  # this be magic
    return str(rssi)


def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):  # what is this condition
        return

    # this comment wat
    if pkt.type == 0 and pkt.subtype == 4:  # subtype used to be 8 (APs) but is now 4 (Probe Requests)
        unhashed_mac = pkt.addr2.upper()
        if unhashed_mac:  # why would this not be
            signal_strength = get_signal_strength(pkt)
            mac = hash_mac(unhashed_mac)
            debug = f"\033[95m Device MAC:{mac} - WiFi signal strength {signal_strength} \033[92m \033[0m"
            print(debug)
            output.append({"hash": mac, "strength": signal_strength})


def main():
    print(f" \n  \033[93m  Wifi Scanner Initialized  \033[0m  \n")
    while True:
        sniff(iface="wlp2s0mon", prn=handle_packet, timeout=20)  # start sniffing
        send_update()


if __name__ == "__main__":
    main()
