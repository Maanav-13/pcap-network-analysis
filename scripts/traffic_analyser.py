import pandas as pd
import sys


def analyze_traffic(input_file, output_file):

    df = pd.read_csv(input_file)

    print("========== TRAFFIC ANALYSIS ==========")

    # Basic information
    print(f"\nTotal flows: {len(df)}")

    # --------------------------------------------------
    # Protocol analysis
    # --------------------------------------------------

    print("\nProtocol Distribution:")

    protocol_counts = (
        df["protocol"]
        .value_counts()
    )

    print(protocol_counts)

    # --------------------------------------------------
    # Source IP analysis
    # --------------------------------------------------

    print("\nTop Source IPs:")

    source_ips = (
        df["src_ip"]
        .value_counts()
        .head(10)
    )

    print(source_ips)

    # --------------------------------------------------
    # Destination IP analysis
    # --------------------------------------------------

    print("\nTop Destination IPs:")

    destination_ips = (
        df["dst_ip"]
        .value_counts()
        .head(10)
    )

    print(destination_ips)

    # --------------------------------------------------
    # Destination port analysis
    # --------------------------------------------------

    print("\nTop Destination Ports:")

    destination_ports = (
        df["dst_port"]
        .value_counts()
        .head(10)
    )

    print(destination_ports)

    # --------------------------------------------------
    # Traffic statistics
    # --------------------------------------------------

    print("\nTraffic Statistics:")

    print(
        f"Average packets/sec: "
        f"{df['packets_per_second'].mean():.2f}"
    )

    print(
        f"Maximum packets/sec: "
        f"{df['packets_per_second'].max():.2f}"
    )

    print(
        f"Average bytes/sec: "
        f"{df['bytes_per_second'].mean():.2f}"
    )

    print(
        f"Maximum bytes/sec: "
        f"{df['bytes_per_second'].max():.2f}"
    )

    # --------------------------------------------------
    # Flow duration statistics
    # --------------------------------------------------

    print("\nFlow Duration Statistics:")

    print(
        f"Average duration: "
        f"{df['duration'].mean():.2f} seconds"
    )

    print(
        f"Maximum duration: "
        f"{df['duration'].max():.2f} seconds"
    )

    # --------------------------------------------------
    # Save analysis data
    # --------------------------------------------------

    analysis = pd.DataFrame({

        "metric": [
            "total_flows",
            "average_packets_per_second",
            "maximum_packets_per_second",
            "average_bytes_per_second",
            "maximum_bytes_per_second",
            "average_duration",
            "maximum_duration"
        ],

        "value": [
            len(df),
            df["packets_per_second"].mean(),
            df["packets_per_second"].max(),
            df["bytes_per_second"].mean(),
            df["bytes_per_second"].max(),
            df["duration"].mean(),
            df["duration"].max()
        ]
    })

    analysis.to_csv(
        output_file,
        index=False
    )

    print(
        f"\nAnalysis summary saved to: {output_file}"
    )


def main():

    if len(sys.argv) != 3:

        print(
            "Usage: python traffic_analyzer.py "
            "<input_csv> <output_csv>"
        )

        return

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    analyze_traffic(
        input_file,
        output_file
    )


if __name__ == "__main__":
    main()