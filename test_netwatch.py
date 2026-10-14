import csv
import socket
import tempfile
import unittest
from pathlib import Path

from netwatch import (
    filter_connections,
    export_csv,
    get_protocol,
    format_address,
)


class TestNetWatch(unittest.TestCase):

    def setUp(self):
        """Create sample connection records for testing."""

        self.records = [
            {
                "protocol": "TCP",
                "local_address": "127.0.0.1:8080",
                "remote_address": "127.0.0.1:50000",
                "status": "ESTABLISHED",
                "pid": 1234,
                "process": "python",
            },
            {
                "protocol": "TCP",
                "local_address": "0.0.0.0:22",
                "remote_address": "-",
                "status": "LISTEN",
                "pid": 5678,
                "process": "sshd",
            },
            {
                "protocol": "UDP",
                "local_address": "127.0.0.1:5353",
                "remote_address": "-",
                "status": "NONE",
                "pid": 9012,
                "process": "systemd",
            },
        ]

    def test_filter_by_local_port(self):
        """Check filtering by local port."""

        result = filter_connections(
            self.records,
            port=8080,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["process"],
            "python",
        )

    def test_filter_by_remote_port(self):
        """Check filtering by remote port."""

        result = filter_connections(
            self.records,
            port=50000,
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["remote_address"],
            "127.0.0.1:50000",
        )

    def test_filter_by_state(self):
        """Check filtering by connection state."""

        result = filter_connections(
            self.records,
            state="LISTEN",
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["process"],
            "sshd",
        )

    def test_combined_filters(self):
        """Check simultaneous port and state filtering."""

        result = filter_connections(
            self.records,
            port=8080,
            state="ESTABLISHED",
        )

        self.assertEqual(len(result), 1)
        self.assertEqual(
            result[0]["protocol"],
            "TCP",
        )

    def test_no_matching_connections(self):
        """Check behavior when no connection matches."""

        result = filter_connections(
            self.records,
            port=9999,
        )

        self.assertEqual(result, [])

    def test_protocol_detection(self):
        """Check TCP and UDP protocol identification."""

        class MockConnection:
            def __init__(self, connection_type):
                self.type = connection_type

        tcp_connection = MockConnection(
            socket.SOCK_STREAM
        )

        udp_connection = MockConnection(
            socket.SOCK_DGRAM
        )

        self.assertEqual(
            get_protocol(tcp_connection),
            "TCP",
        )

        self.assertEqual(
            get_protocol(udp_connection),
            "UDP",
        )

    def test_format_address(self):
        """Check formatting when an address is missing."""

        self.assertEqual(
            format_address(None),
            "-",
        )

    def test_csv_export(self):
        """Check that connection records are exported correctly."""

        with tempfile.TemporaryDirectory() as directory:

            output = Path(directory) / "connections.csv"

            export_csv(
                self.records,
                str(output),
            )

            self.assertTrue(output.exists())

            with output.open(
                newline="",
                encoding="utf-8",
            ) as file:

                rows = list(
                    csv.DictReader(file)
                )

            self.assertEqual(
                len(rows),
                3,
            )

            self.assertEqual(
                rows[0]["protocol"],
                "TCP",
            )

            self.assertEqual(
                rows[0]["local_address"],
                "127.0.0.1:8080",
            )

            self.assertEqual(
                rows[0]["process"],
                "python",
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
