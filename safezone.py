import pywifi
from pywifi import const
import time

def scan_networks():
    wifi = pywifi.PyWiFi()
    iface = wifi.interfaces()[0]  # get the first wireless interface

    iface.scan()
    time.sleep(2)  # wait for scan results
    results = iface.scan_results()

    return results

def detect_threats(networks):
    ssids_seen = set()
    for network in networks:
        ssid = network.ssid
        signal = network.signal
        auth = network.auth

        # Check: Open Network
        if network.akm == [const.AKM_TYPE_NONE]:
            print(f"🚨 Unsecure Network Detected: {ssid}")

        # Check: Duplicate SSID (evil twin possible)
        if ssid in ssids_seen:
            print(f"🚨 Duplicate SSID Detected: {ssid}")
        else:
            ssids_seen.add(ssid)

        # Check: Very Weak Signal
        if signal < -80:  # dBm; lower is worse
            print(f"🚨 Weak Signal AP Detected: {ssid} (Signal: {signal} dBm)")

def main():
    print("🔍 Scanning for nearby WiFi networks...")
    networks = scan_networks()
    detect_threats(networks)

if __name__ == "__main__":
    main()
