import argparse
import csv
import socket
from datetime import datetime

import psutil


def get_protocol(conn):
    if conn.type == socket.SOCK_STREAM:
        return "TCP"
    if conn.type == socket.SOCK_DGRAM:
        return "UDP"
    return str(conn.type)


def format_address(address):
    if not address:
        return "-"

    return f"{address.ip}:{address.port}"


def inspect_connections():
    records = []

    for conn in psutil.net_connections(kind="inet"):
        protocol = get_protocol(conn)

        local_address = format_address(conn.laddr)
        remote_address = format_address(conn.raddr)

        try:
            process = psutil.Process(conn.pid).name() if conn.pid else "-"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            process = "Unavailable"

        records.append({
            "protocol": protocol,
            "local_address": local_address,
            "remote_address": remote_address,
            "status": conn.status,
            "pid": conn.pid if conn.pid is not None else "-",
            "process": process,
        })

    return records


def filter_connections(records, port=None, state=None):
    filtered = []

    for record in records:
        if port is not None:
            local_port = record["local_address"].rsplit(":", 1)[-1]
            remote_port = record["remote_address"].rsplit(":", 1)[-1]

            if str(port) not in (local_port, remote_port):
                continue

        if state and record["status"].upper() != state.upper():
            continue

        filtered.append(record)

    return filtered


def show_connections(records):
    if not records:
        print("No connections match your filters.")
        return

    print(
        f"{'PROTO':<7} {'LOCAL ADDRESS':<27} "
        f"{'REMOTE ADDRESS':<27} {'STATE':<13} "
        f"{'PID':<8} PROCESS"
    )
    print("-" * 105)

    for record in records:
        print(
            f"{record['protocol']:<7} "
            f"{record['local_address']:<27} "
            f"{record['remote_address']:<27} "
            f"{record['status']:<13} "
            f"{str(record['pid']):<8} "
            f"{record['process']}"
        )


def show_summary(records):
    print("\nConnection Summary")
    print("------------------")
    print(f"Total connections: {len(records)}")

    for protocol in ("TCP", "UDP"):
        count = sum(
            1 for record in records
            if record["protocol"] == protocol
        )
        print(f"{protocol} connections: {count}")

    listening = sum(
        1 for record in records
        if record["status"] == "LISTEN"
    )
    established = sum(
        1 for record in records
        if record["status"] == "ESTABLISHED"
    )

    print(f"Listening sockets: {listening}")
    print(f"Established TCP connections: {established}")


def export_csv(records, filename):
    fields = [
        "protocol",
        "local_address",
        "remote_address",
        "status",
        "pid",
        "process",
    ]

    with open(filename, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        writer.writerows(records)

    print(f"\nExported {len(records)} records to {filename}")


def main():
    parser = argparse.ArgumentParser(
        description="Inspect local TCP and UDP network connections."
    )

    parser.add_argument(
        "--port",
        type=int,
        help="Filter by local or remote port",
    )
    parser.add_argument(
        "--state",
        choices=[
            "ESTABLISHED",
            "LISTEN",
            "TIME_WAIT",
            "CLOSE_WAIT",
            "SYN_SENT",
            "SYN_RECV",
            "NONE",
        ],
        help="Filter by connection state",
    )
    parser.add_argument(
        "--export",
        metavar="FILE",
        help="Export results to a CSV file",
    )

    args = parser.parse_args()

    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("Port must be between 1 and 65535.")

    try:
        records = inspect_connections()
    except psutil.Error as error:
        parser.error(f"Could not inspect connections: {error}")

    records = filter_connections(
        records,
        port=args.port,
        state=args.state,
    )

    print(f"NetWatch | Snapshot: {datetime.now().isoformat(timespec='seconds')}")
    show_connections(records)
    show_summary(records)

    if args.export:
        export_csv(records, args.export)


if __name__ == "__main__":
    main()
