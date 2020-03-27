import hashlib
import os
from datetime import datetime

import requests
from dotenv import load_dotenv
from scapy.layers.dot11 import Dot11ProbeReq, sniff, RadioTap

output = []

load_dotenv('test.env')  # loads the environment variables from the chosen .env file
apikey = os.environ.get('APIKEY')  # api key needed to post to the gateway
request_url = os.environ.get('REQUEST_URL')  # url for the request


def hash_mac(plaintext: str) -> str:  # function for mac address hashing using sha256
    return hashlib.sha256(plaintext.encode()).hexdigest()


def send_update():  # function to send the scanned data to the gateway
    print("sending update")

    global output
    api_key = apikey
    url = request_url

    headers = {"Authorization": f"Bearer {api_key}"}  # specify the api key in the header
    payload = {"data": output, "time": datetime.now().isoformat()}  # the data we scanned and hashed
    r = requests.post(url, headers=headers, json=payload)  # posting the request

    print(f"sent: {r.status_code}")
    # assert r.ok   4debug, add try except for timeout autism in prod
    output = []


def handle_packet(pkt):  # function for getting the mac adress and signal strength from a probe request packet
    if not pkt.haslayer(Dot11ProbeReq):
        return

    if pkt.type == 0 and pkt.subtype == 4:  # filters out beacon requests
        unhashed_mac = pkt.addr2.upper()
        signal_strength = pkt.getlayer(RadioTap).dBm_AntSignal
        mac = hash_mac(unhashed_mac)

        # debug = f" Device MAC:{unhashed_mac} - WiFi signal strength {signal_strength}"
        output.append({"hash": mac, "strength": signal_strength})


def main():  # function that combines sniffing and sending signals to initiate the script
    print(f"Wifi Scanner Initialized")

    while True:  # loops between sniffing signals and sending the signals to the gateway
        sniff(iface="wlan1mon", prn=handle_packet, timeout=60)  # start sniffing and stops at the timout
        send_update()


if __name__ == "__main__":
    main()
