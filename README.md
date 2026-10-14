# NetWatch — Network Connection Inspector

NetWatch is a Python command-line tool that inspects TCP and UDP
network connections exposed by the local operating system.

It displays local and remote IP addresses, port numbers, connection
states, and associated process information when available.

## Features

- Inspect TCP and UDP connections
- Display local and remote endpoints
- Show connection states and process information
- Filter connections by port
- Filter connections by state
- Display a connection summary
- Export connection information to CSV
- Handle unavailable process information

## Requirements

- Python 3
- psutil

## Installation

Clone this repository and navigate into the project directory.

Create a virtual environment:

    python3 -m venv .venv

Activate it:

    source .venv/bin/activate

Install dependencies:

    python -m pip install -r requirements.txt

## Usage

Display network connections:

    python netwatch.py

Filter by port:

    python netwatch.py --port 443

Display listening sockets:

    python netwatch.py --state LISTEN

Export results to CSV:

    python netwatch.py --export conn.csv

Combine filters:

    python netwatch.py --port 443 --state ESTABLISHED

Display available options:

    python netwatch.py --help

## Testing

Run the automated tests:

    python -m unittest -v

The tests cover protocol identification, connection filtering,
address formatting, and CSV export.

## Implementation

NetWatch uses the psutil library to retrieve network connection
information from the operating system.

It formats the results, applies optional filters, calculates summary
statistics, and optionally exports the data to CSV.

## Limitations

- Displays a point-in-time snapshot rather than continuously
  monitoring connections.
- Available process information depends on operating system
  permissions.
- Does not capture network packets or inspect traffic contents.
- Does not determine whether a connection is malicious.
- IPv6 endpoint formatting could be improved.

## Learning objectives

This project explores IP addresses, port numbers, TCP connection
states, UDP sockets, operating system networking APIs, command-line
arguments, CSV processing, and automated testing.
