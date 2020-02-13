#########################################################################
#     Wifiscanner.py - A simple python script which records and logs wifi probe requests.
#     Author - D4rKP01s0n
#     Requirements - Scapy and Datetime
#     Inspiration - Tim Tomes (LaNMaSteR53)'s WUDS https://bitbucket.org/LaNMaSteR53/wuds/
#     Reminder - Change mon0 (around line 65) to your monitor-mode enabled wifi interface
#########################################################################


from scapy.layers.dot11 import *
import logging
import time
import json

# Devices which are known to be constantly probing
IGNORE_LIST = {'00:00:00:00:00:00', '01:01:01:01:01:01'}
SEEN_DEVICES = []  # Devices which have had their probes recieved
d = {'00:00:00:00:00:00': 'Example MAC Address'}  # Dictionary of all named devices

knownfile = open('knowndevices.txt', 'a')
knownfile.write(str(SEEN_DEVICES))


# Writes a json file with a dictionary of all named devices


def signal_strength(pkt):
    try:
        extra = pkt.notdecoded
        rssi = -(256 - ord(extra[-4:-3]))
        return str(rssi)
    except rssi == -100:
        return 'out of reach'


def handle_packet(pkt):
    if not pkt.haslayer(Dot11ProbeReq):
        return

    if pkt.type == 0 and pkt.subtype == 4:  # subtype used to be 8 (APs) but is now 4 (Probe Requests)
        # logging.debug('Probe Recorded with MAC ' + curmac)
        curmac = pkt.addr2
        curmac = curmac.upper()  # Assign variable to packet mac and make it uppercase
        SEEN_DEVICES.append(curmac)  # Add to set of known devices (sets ignore duplicates so it is not a problem)
        strength = signal_strength(pkt)

        if curmac not in IGNORE_LIST:  # If not registered as ignored
            if curmac in d:
                logging.info('Probe Recorded from ' + d[
                    curmac] + ' with MAC ' + curmac + " WiFi signal strength" +
                             strength)  # Log to file wifiscanner.log
                print('\033[95m' + 'Probe MAC Address: ' + pkt.addr2 + ' from device ' + '\033[93m' + d[
                    curmac] + '\033[0m' + '\033[92m')
                # 'with SSID: {pkt.info}'.format(pkt=pkt)) #Print to command line with purple color

            else:
                logging.info('Probe Recorded from MAC ' + pkt.addr2 + " WiFi signal strength:" +
                             strength)  # Log to file wifiscanner.log
                print('\033[95m' + f"Device MAC:{pkt.addr2}" +
                      f" with SSID: {pkt.info}" + '\033[92m' + " WiFi signal strength:" +
                      strength + '\033[92m'.format(
                    pkt=pkt) + '\033[0m')


def main():
    logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename='wifiscanner.log',
                        level=logging.DEBUG)  # setup logging to file
    logging.info(
        '\n' + '\033[93m' + 'Wifi Scanner Initialized' + '\033[0m' + '\n')  # announce that it has started to log file with yellow color
    print(
        '\n' + '\033[93m' + 'Wifi Scanner Initialized' + '\033[0m' + '\n')  # announce that it has started to command line with yellow color		(/n is newline)

    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default='wlp2s0mon',
                        # Change mon0 to your monitor-mode enabled wifi interface
                        help='monitor mode enabled interface')
    args = parser.parse_args()
    sniff(iface=args.interface, prn=handle_packet)  # start sniffing

    while 1:
        time.sleep(1)  # Supposed to make an infinite loop, but for some reason it stops after a while


if __name__ == '__main__':
    main()
