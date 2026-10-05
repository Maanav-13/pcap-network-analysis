import pandas as pd
import sys


# --------------------------------------------------
# Detection thresholds
# --------------------------------------------------

PACKETS_PER_SECOND_THRESHOLD = 500
BYTES_PER_SECOND_THRESHOLD = 100000

PORT_SCAN_THRESHOLD = 10


def detect_port_scans(df):

    # Count the number of unique destination ports
    # contacted by each source IP.

    port_counts = (
        df.groupby("src_ip")["dst_port"]
        .nunique()
    )

    return port_counts


def detect_intrusions(input_file, output_file):

    df = pd.read_csv(input_file)

    alerts = []

    # --------------------------------------------------
    # Port scan analysis
    # --------------------------------------------------

    port_counts = detect_port_scans(df)

    # Keep track of source IPs for which a port scan
    # alert has already been generated.
    port_scan_alerted = set()

    # --------------------------------------------------
    # Analyze each flow
    # --------------------------------------------------

    for _, row in df.iterrows():

        src_ip = row["src_ip"]
        dst_ip = row["dst_ip"]

        src_port = row["src_port"]
        dst_port = row["dst_port"]

        protocol = row["protocol"]

        packets_per_second = row[
            "packets_per_second"
        ]

        bytes_per_second = row[
            "bytes_per_second"
        ]

        # --------------------------------------------------
        # Rule 1: High packet rate
        # --------------------------------------------------

        if packets_per_second > PACKETS_PER_SECOND_THRESHOLD:

            alerts.append({

                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "src_port": src_port,
                "dst_port": dst_port,

                "protocol": protocol,

                "alert_type": "High Packet Rate",

                "severity": "HIGH",

                "details": (
                    f"Packet rate of "
                    f"{packets_per_second:.2f} packets/sec "
                    f"exceeds threshold of "
                    f"{PACKETS_PER_SECOND_THRESHOLD}"
                )
            })

        # --------------------------------------------------
        # Rule 2: High bandwidth
        # --------------------------------------------------

        if bytes_per_second > BYTES_PER_SECOND_THRESHOLD:

            alerts.append({

                "src_ip": src_ip,
                "dst_ip": dst_ip,

                "src_port": src_port,
                "dst_port": dst_port,

                "protocol": protocol,

                "alert_type": "High Bandwidth",

                "severity": "HIGH",

                "details": (
                    f"Traffic rate of "
                    f"{bytes_per_second:.2f} bytes/sec "
                    f"exceeds threshold of "
                    f"{BYTES_PER_SECOND_THRESHOLD}"
                )
            })

        # --------------------------------------------------
        # Rule 3: Port scan
        # --------------------------------------------------

        if port_counts[src_ip] >= PORT_SCAN_THRESHOLD:

            # Only create one port scan alert for each
            # source IP, even if that IP has many flows.

            if src_ip not in port_scan_alerted:

                alerts.append({

                    "src_ip": src_ip,
                    "dst_ip": dst_ip,

                    "src_port": src_port,
                    "dst_port": dst_port,

                    "protocol": protocol,

                    "alert_type": "Port Scan",

                    "severity": "HIGH",

                    "details": (
                        f"Source IP contacted "
                        f"{port_counts[src_ip]} "
                        f"unique destination ports"
                    )
                })

                port_scan_alerted.add(src_ip)

    # --------------------------------------------------
    # Create alert DataFrame
    # --------------------------------------------------

    alerts_df = pd.DataFrame(alerts)

    # If no alerts were found, create an empty
    # DataFrame with the expected columns.

    if alerts_df.empty:

        alerts_df = pd.DataFrame(columns=[

            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "alert_type",
            "severity",
            "details"

        ])

    # --------------------------------------------------
    # Save alerts
    # --------------------------------------------------

    alerts_df.to_csv(
        output_file,
        index=False
    )

    # --------------------------------------------------
    # Display results
    # --------------------------------------------------

    print("========== IDS DETECTION ==========")

    print(
        f"\nFlows analyzed: {len(df)}"
    )

    print(
        f"Alerts generated: {len(alerts_df)}"
    )

    if not alerts_df.empty:

        print("\nAlert Summary:")

        print(
            alerts_df["alert_type"]
            .value_counts()
        )

        print("\nSeverity Summary:")

        print(
            alerts_df["severity"]
            .value_counts()
        )

    else:

        print(
            "\nNo suspicious activity detected."
        )

    print(
        f"\nAlerts saved to: {output_file}"
    )


def main():

    if len(sys.argv) != 3:

        print(
            "Usage: py ids_detector.py "
            "<input_csv> <output_csv>"
        )

        return

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    detect_intrusions(
        input_file,
        output_file
    )


if __name__ == "__main__":
    main()