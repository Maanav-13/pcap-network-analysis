import pandas as pd
import sys


def create_flow_features(input_file, output_file):

    df = pd.read_csv(input_file)

    # Remove packets without IP information
    df = df.dropna(
        subset=["src_ip", "dst_ip", "protocol"]
    ).copy()

    # Convert timestamp
    df["timestamp"] = pd.to_numeric(
        df["timestamp"],
        errors="coerce"
    )

    # Convert ports
    df["src_port"] = pd.to_numeric(
        df["src_port"],
        errors="coerce"
    ).fillna(0)

    df["dst_port"] = pd.to_numeric(
        df["dst_port"],
        errors="coerce"
    ).fillna(0)

    # Create a bidirectional flow key
    def create_flow_key(row):

        endpoint1 = (
            row["src_ip"],
            int(row["src_port"])
        )

        endpoint2 = (
            row["dst_ip"],
            int(row["dst_port"])
        )

        endpoints = sorted(
            [endpoint1, endpoint2]
        )

        return (
            endpoints[0][0],
            endpoints[0][1],
            endpoints[1][0],
            endpoints[1][1],
            row["protocol"]
        )

    df["flow_key"] = df.apply(
        create_flow_key,
        axis=1
    )

    flows = []

    for flow_key, group in df.groupby("flow_key"):

        group = group.sort_values(
            "timestamp"
        )

        first_packet = group.iloc[0]
        last_packet = group.iloc[-1]

        # The first packet defines the forward direction
        forward_src = first_packet["src_ip"]
        forward_dst = first_packet["dst_ip"]
        forward_src_port = first_packet["src_port"]
        forward_dst_port = first_packet["dst_port"]

        forward = group[
            (group["src_ip"] == forward_src)
            & (group["dst_ip"] == forward_dst)
            & (group["src_port"] == forward_src_port)
            & (group["dst_port"] == forward_dst_port)
        ]

        backward = group[
            (group["src_ip"] == forward_dst)
            & (group["dst_ip"] == forward_src)
            & (group["src_port"] == forward_dst_port)
            & (group["dst_port"] == forward_src_port)
        ]

        duration = (
            last_packet["timestamp"]
            - first_packet["timestamp"]
        )

        packet_count = len(group)

        total_bytes = group[
            "packet_length"
        ].sum()

        forward_packets = len(forward)
        backward_packets = len(backward)

        forward_bytes = forward[
            "packet_length"
        ].sum()

        backward_bytes = backward[
            "packet_length"
        ].sum()

        average_packet_size = (
            total_bytes / packet_count
        )

        packets_per_second = (
            packet_count / duration
            if duration > 0
            else 0
        )

        bytes_per_second = (
            total_bytes / duration
            if duration > 0
            else 0
        )

        flows.append({

            "src_ip": forward_src,
            "dst_ip": forward_dst,

            "src_port": forward_src_port,
            "dst_port": forward_dst_port,

            "protocol": first_packet["protocol"],

            "start_time": first_packet["timestamp"],
            "end_time": last_packet["timestamp"],

            "duration": duration,

            "packet_count": packet_count,
            "total_bytes": total_bytes,

            "forward_packets": forward_packets,
            "backward_packets": backward_packets,

            "forward_bytes": forward_bytes,
            "backward_bytes": backward_bytes,

            "average_packet_size": average_packet_size,

            "packets_per_second": packets_per_second,
            "bytes_per_second": bytes_per_second
        })

    flow_df = pd.DataFrame(flows)

    flow_df.to_csv(
        output_file,
        index=False
    )

    print(
        "========== FLOW EXTRACTION =========="
    )

    print(
        f"Packets analyzed: {len(df)}"
    )

    print(
        f"Flows created: {len(flow_df)}"
    )

    print(
        f"Output saved to: {output_file}"
    )


def main():

    if len(sys.argv) != 3:

        print(
            "Usage: python flow_extractor.py "
            "<input_csv> <output_csv>"
        )

        return

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    create_flow_features(
        input_file,
        output_file
    )


if __name__ == "__main__":
    main()