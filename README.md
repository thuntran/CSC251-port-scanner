# CSC 251 Final Project: Port Scanner

_(to be updated...)_

## Necessary files

The only file required to run the port scanner is `port_scanner.py`.

## Instructions

- _Note about the `pytz` module_: Install `pytz` to view the timezone shown in the port scanner output:

  ```bash
  pip install pytz
  ```

- To run the port scanner, from the terminal (MacOS/Linux) or command prompt (Windows):

  ```bash
  python3 port_scanner.py -mode [normal/syn/fin] -order [order/random] -ports [all/known] [ip_address]
  ```

  - The target IP address to be tested on is 131.229.72.13.
  - The target hostname to be tested on is `glasgow.smith.edu`.
  - IMPORTANT: This port scanner is only intended to scan the host specified above. It is important that the port scanner should not be misused (i.e. to scan other hosts without permission.)

- Options:
  - Order of options (`-mode`, `-order`, `-ports`) does not matter.

## Challenges & how to overcome

## Resources

- [How to Check if a Host is Reachable using Python - Best Methods](https://copyprogramming.com/howto/how-to-check-if-a-host-is-reachable-using-python-best-methods)
- [Port Scanner using Python](https://www.geeksforgeeks.org/port-scanner-using-python/)
- [Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)
- [argparse - Parser for command-line options, arguments and sub-commands - Python documentation](https://docs.python.org/3/library/argparse.html)
- [SYN Stealth Scan with Power of Python Scapy](https://dev.to/powerexploit/syn-stealth-scan-with-power-of-python-scapy-58aj)
- [Python Penetration Testing - Port Scanning](https://www.oreilly.com/library/view/python-penetration-testing/9781789138962/9f389f41-4489-4628-a61f-969eea3aae8c.xhtml)
- [Port Scanning using Scapy](https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/)
- [Let's! Ping The Network with 15 Line Of Code Using Python & Scapy!](https://dev.to/powerexploit/let-s-ping-the-network-with-python-scapy-5g18)
- [socket — Low-level networking interface](https://docs.python.org/3/library/socket.html)

## Contributors

- [Thu Tran](https://github.com/thuntran) (I worked independently on this final project.)
