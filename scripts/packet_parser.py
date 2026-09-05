from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply
import csv
import sys


def extract_packet_features(pcap_file):
    packets = rdpcap(pcap_file)

    features = []

    for packet in packets:
        row = {
            "timestamp": float(packet.time),
            "packet_length": len(packet),
            "ip_version": "",
            "src_ip": "",
            "dst_ip": "",
            "protocol": "",
            "src_port": "",
            "dst_port": "",
            "ttl": "",
            "tcp_flags": ""
        }

        # IPv4
        if IP in packet:
            ip = packet[IP]

            row["ip_version"] = 4
            row["src_ip"] = ip.src
            row["dst_ip"] = ip.dst
            row["ttl"] = ip.ttl

            if TCP in packet:
                row["protocol"] = "TCP"
                row["src_port"] = packet[TCP].sport
                row["dst_port"] = packet[TCP].dport
                row["tcp_flags"] = str(packet[TCP].flags)

            elif UDP in packet:
                row["protocol"] = "UDP"
                row["src_port"] = packet[UDP].sport
                row["dst_port"] = packet[UDP].dport

            elif ICMP in packet:
                row["protocol"] = "ICMP"

            else:
                row["protocol"] = str(ip.proto)

        # IPv6
        elif IPv6 in packet:
            ip = packet[IPv6]

            row["ip_version"] = 6
            row["src_ip"] = ip.src
            row["dst_ip"] = ip.dst
            row["ttl"] = ip.hlim

            if TCP in packet:
                row["protocol"] = "TCP"
                row["src_port"] = packet[TCP].sport
                row["dst_port"] = packet[TCP].dport
                row["tcp_flags"] = str(packet[TCP].flags)

            elif UDP in packet:
                row["protocol"] = "UDP"
                row["src_port"] = packet[UDP].sport
                row["dst_port"] = packet[UDP].dport

            elif (
                ICMPv6EchoRequest in packet
                or ICMPv6EchoReply in packet
                or ip.nh == 58
            ):
                row["protocol"] = "ICMPv6"

            else:
                row["protocol"] = str(ip.nh)

        features.append(row)

    return features


def save_to_csv(features, output_file):
    fieldnames = [
        "timestamp",
        "packet_length",
        "ip_version",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "ttl",
        "tcp_flags"
    ]

    with open(output_file, "w", newline="") as csvfile:
        writer = csv.DictWriter(
            csvfile,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(features)


def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print("python packet_parser.py <input_pcap> <output_csv>")
        return

    input_pcap = sys.argv[1]
    output_csv = sys.argv[2]

    print(f"Reading PCAP: {input_pcap}")

    features = extract_packet_features(input_pcap)

    print(f"Packets processed: {len(features)}")

    save_to_csv(features, output_csv)

    print(f"Features saved to: {output_csv}")


if __name__ == "__main__":
    main()