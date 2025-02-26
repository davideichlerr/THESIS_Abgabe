import pyshark
from pythonosc import udp_client
import re
import time
from collections import deque

# OSC-Einstellungen
ip = "127.0.0.1"
port = 7400
client = udp_client.SimpleUDPClient(ip, port)

# Soziale Medien Domains
social_media_domains = ['instagram', 'facebook', 'google', 'apple', 'spotify', 'whatsapp']
domain_patterns = [re.compile(domain) for domain in social_media_domains]

# Variablen
dns_requests_count = 0
dns_requests_social_media = {domain: 0 for domain in social_media_domains}
packet_timestamps = deque(maxlen=60)  # Für Inter-Packet-Interval
payload_sizes = deque(maxlen=600)     # Sliding Window für Payloads (60 Sekunden)
timestamps = deque(maxlen=600)        # Sliding Window für Timestamps (60 Sekunden)

# Normalisierung
payload_min, payload_max = float('inf'), float('-inf')
data_rate_min, data_rate_max = float('inf'), float('-inf')

# DNS-Spike-Detection
dns_spike_threshold = 3
spike_window = 0.5
dns_requests_recent = deque(maxlen=60)

# Hilfsfunktion: Normalisierung
def normalize(value, min_val, max_val):
    return (value - min_val) / (max_val - min_val) if max_val > min_val else 0

# Funktion: Inter-Packet-Interval berechnen
def calculate_inter_packet_interval():
    if len(packet_timestamps) < 2:
        return 0  # Zu wenige Daten für eine Berechnung
    intervals = [t2 - t1 for t1, t2 in zip(packet_timestamps, list(packet_timestamps)[1:])]
    return sum(intervals) / len(intervals)

# Funktion: DNS-Spike-Detection
def check_for_dns_spike():
    global dns_requests_recent  # Sicherstellen, dass die globale Variable verwendet wird
    current_time = time.time()
    dns_requests_recent.append(current_time)
    dns_requests_recent = deque([t for t in dns_requests_recent if current_time - t <= spike_window], maxlen=60)
    return 1 if len(dns_requests_recent) >= dns_spike_threshold else 0

# Sliding Window Berechnungen
def calculate_sliding_window():
    if len(payload_sizes) < 1 or len(timestamps) < 2:
        return 0, 0, 0, 0  # Keine Berechnungen möglich

    # Durchschnittliche Payload-Größe
    avg_payload_size = sum(payload_sizes) / len(payload_sizes)

    # Data Rate (Sliding Window)
    total_data = sum(payload_sizes)
    time_span = timestamps[-1] - timestamps[0]
    data_rate = total_data / time_span if time_span > 0 else 0

    # Normalisierung
    global payload_min, payload_max, data_rate_min, data_rate_max
    payload_min = min(payload_min, avg_payload_size)
    payload_max = max(payload_max, avg_payload_size)
    data_rate_min = min(data_rate_min, data_rate)
    data_rate_max = max(data_rate_max, data_rate)

    normalized_payload = normalize(avg_payload_size, payload_min, payload_max)
    normalized_data_rate = normalize(data_rate, data_rate_min, data_rate_max)

    return avg_payload_size, data_rate, normalized_payload, normalized_data_rate

# Paket-Verarbeitung
def process_packet(packet):
    global dns_requests_count

    try:
        # DNS-Pakete
        if 'DNS' in packet:
            dns_requests_count += 1
            query_name = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else ''
            if query_name:
                for pattern in domain_patterns:
                    if pattern.search(query_name):
                        domain = pattern.pattern
                        dns_requests_social_media[domain] += 1
                        break

        # Allgemeine Payload-Größe
        payload_size = len(packet)
        payload_sizes.append(payload_size)

        # Zeitstempel hinzufügen
        current_time = time.time()
        packet_timestamps.append(current_time)
        timestamps.append(current_time)

    except AttributeError as e:
        print(f"Packet processing error: {e}")

# Senden der OSC-Nachrichten
def send_osc_messages():
    print("Sending OSC messages...")

    avg_payload_size, data_rate, normalized_payload, normalized_data_rate = calculate_sliding_window()
    inter_packet_interval = calculate_inter_packet_interval()
    dns_spike = check_for_dns_spike()

    # DNS-Daten senden
    client.send_message("/dns_requests/total", dns_requests_count)
    for domain, count in dns_requests_social_media.items():
        client.send_message(f"/dns_requests/{domain}", count)

    # Parameter senden
    client.send_message("/payload_size", avg_payload_size)
    client.send_message("/payload_size_normalized", normalized_payload)
    client.send_message("/data_rate", data_rate)
    client.send_message("/data_rate_normalized", normalized_data_rate)
    client.send_message("/inter_packet_interval", inter_packet_interval)
    client.send_message("/dns_spike", dns_spike)

    # Debug-Ausgabe
    print(f"Payload Avg: {avg_payload_size:.2f}, Data Rate: {data_rate:.2f}")
    print(f"Normalized Payload: {normalized_payload:.2f}, Normalized Data Rate: {normalized_data_rate:.2f}")
    print(f"Inter-Packet-Interval: {inter_packet_interval:.2f}, DNS Spike: {dns_spike}")

# Live-Capture starten
def analyze_live_capture(interface="rvi0", interval=0.1):
    capture = pyshark.LiveCapture(interface=interface)
    start_time = time.time()

    for packet in capture.sniff_continuously():
        process_packet(packet)
        if time.time() - start_time >= interval:
            send_osc_messages()
            start_time = time.time()

# Main
if __name__ == "__main__":
    analyze_live_capture(interface="rvi0")
