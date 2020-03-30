import hashlib
import os
from datetime import datetime

import requests
from dotenv import load_dotenv
from scapy.layers.dot11 import Dot11ProbeReq, sniff, RadioTap

load_dotenv('test.env')  # loads the environment variables from the chosen .env file
api_key = os.environ.get('APIKEY')  # api key needed to post to the gateway
request_url = os.environ.get('REQUEST_URL')  # url for the request


class RPI:  # class that represents the Raspberry Pi

    def __init__(self):
        self.output = []  # hashed macs and signal strength information is kept before sending it out

    def handle_packet(self, pkt):  # function for getting the mac adress and signal strength from a probe request packet
        if not pkt.haslayer(Dot11ProbeReq):
            return

        if pkt.type == 0 and pkt.subtype == 4:  # filters out beacon requests
            unhashed_mac = pkt.addr2.upper()
            signal_strength = pkt.getlayer(RadioTap).dBm_AntSignal
            mac = self.hash_mac(unhashed_mac)

            #  print(f" Device MAC:{unhashed_mac} - WiFi signal strength {signal_strength}") for testing/debugging
            self.output.append({"hash": mac, "strength": signal_strength})

    def sniffer(self, timeout=60, interface='wlan1mon'):
        # activates the sniffer that actually scans for wifi packets and calls the
        # handle_packet function that accepts that packet information as an argument
        sniff(iface=interface, prn=self.handle_packet, timeout=timeout)

    def send_update(self, apikey, url):  # function to send the scanned data to the gateway
        print("sending update")

        apikey = apikey
        url = url

        headers = {"Authorization": f"Bearer {apikey}"}  # specify the api key in the header
        payload = {"data": self.output, "time": datetime.now().isoformat()}  # the data we scanned and hashed
        r = requests.post(url, headers=headers, json=payload)  # posting the request
        self.output = []  # clears the list after it has been sent

        print(f"sent: {r.status_code}")
        # assert r.ok   4debug, add try except for timeout autism in prod

    @staticmethod
    def hash_mac(plaintext: str) -> str:  # function for mac address hashing using sha256
        return hashlib.sha256(plaintext.encode()).hexdigest()


def main():
    wifi_sensor = RPI()
    while True:
        wifi_sensor.sniffer()
        wifi_sensor.send_update(api_key, request_url)


if __name__ == "__main__":
    main()
