# TCP Packet Sniffer CLI Tool (Pycap)

This CLI tool is used to listen to network traffic and capture packets going to or coming from a specified port. It is developed in Python and supports various network protocols.

## Requirements

- Python 3.x
- Standard libraries such as `struct`, `socket`, and `typing`

## Installation

1. Clone the repository to your local machine:

    ```
    git clone https://github.com/Alsond5/Pycap.git
    ```

2. Navigate to the project's root directory:

    ```
    cd packet-sniffer-cli
    ```

## Usage

1. To start the CLI tool, run the following command:

    ```
    python app.py
    ```

2. Once the tool is started, it will begin listening to network traffic and capture packets going to or coming from the specified port.

3. For each captured packet, the specified callback function will be invoked. This function should handle Ethernet, IP, and TCP headers along with packet data.

## Example Usage

Below is an example of using the CLI tool to listen on port 80:

```
python app.py
```

This command will start listening on port 80 and be ready to capture packets.

## Note

- Exercise caution while listening to network traffic and prioritize privacy and security. Avoid engaging in illegal activities or attempting unauthorized access.
- Obtain permission or authorization before using the tool on specific networks or systems.
- The tool should only be used for legal and legitimate purposes such as education or security testing.

## Contributions

- You can report bugs or make suggestions by opening an issue on GitHub.
