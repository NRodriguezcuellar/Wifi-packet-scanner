from scapy.layers.dot11 import *
import hashlib
import json
import requests
from datetime import datetime


def signal_strength(pkt):
    extra = pkt.notdecoded
    rssi = -(256 - ord(extra[-4:-3]))
    return str(rssi)


mac_list = []


def create_json(hashes, strength_signal):
    mac = {'hash': hashes, 'strength': strength_signal}
    mac_list.append(mac)


def hash_mac(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def send_update():
    print('sending update')
    api_key = "f015a18b3f8e051eb802ea5e459b67bbaec460f3f4bfacb6d0ff45b1afa1bd47"
    url = "http://127.0.0.1:8000/read"
    headers = {"Authorization": f"Bearer {api_key}"}
    payload = {
        "data": json.dumps(mac_list),
        "time": datetime.now().isoformat()
    }
    r = requests.post(url, headers=headers, json=payload)
    assert r.ok
    print('sent')


def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return

    if pkt.type == 0 and pkt.subtype == 4:  # subtype used to be 8 (APs) but is now 4 (Probe Requests)
        curmac = pkt.addr2
        curmac = curmac.upper()  # Assign variable to packet mac and make it uppercase
        strength = signal_strength(pkt)

        if curmac:
            create_json(hash_mac(curmac), strength)
            print(
                f"\033[95m Device MAC:{hash_mac(curmac)}  -  WiFi signal strength {strength} \033[92m \033[0m")


def main():
    print(f" \n  \033[93m  Wifi Scanner Initialized  \033[0m  \n")

    while True:
        sniff(iface='wlp2s0mon', prn=handle_packet, timeout=20)  # start sniffing
        send_update()


if __name__ == '__main__':
    main()