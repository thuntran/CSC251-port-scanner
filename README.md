# CSC 251 Final Project: Port Scanner

## Necessary files

The only file required to run the port scanner is `port_scanner.py`.

## Instructions

- Install the `scapy` module for packet manipulation:

  ```bash
  pip install scapy
  ```

- Install `pytz` to view the timezone shown in the port scanner output:

  ```bash
  pip install pytz
  ```

- To run the port scanner, from the terminal (MacOS/Linux) or command prompt (Windows):

  ```bash
  python3 port_scanner.py -mode [normal/syn/fin] -order [order/random] -ports [all/known] [ip_address]
  ```

- Notes about testing the port scanner:
  - The target IP address to be tested on is **131.229.72.13**.
  - The target hostname to be tested on is **glasgow.smith.edu**.
  - Order of options (`-mode`, `-order`, `-ports`) does not matter.
  - _IMPORTANT_: This port scanner is only intended to scan the host specified above. It is important that the port scanner should not be misused (i.e. to scan other hosts without permission.)

## Challenges & how to overcome

- One major challenge that I faced in this project is that my unfamiliarity with using the `socket` module for socket programming and the `scapy` module for packet manipulation.
  - However, there is quite a number of online resources (especially those with diagrams to illustrate the differences between the 3 scanning modes), which I think I was able to utilize well to complete this final project.
  - Also, reviewing my previous coding assignments that involved using `socket` and `scapy` did help too.
- I used the `argparse` module but didn't have a whole lot of experience with it, and it took me a bit at the beginning of the project to grasp what I need to do to construct the correct arguments for the command line.
  - Reading the Python documentation on `argparse` helped a lot.

## Resources

- [argparse - Parser for command-line options, arguments and sub-commands - Python documentation](https://docs.python.org/3/library/argparse.html)
- [socket — Low-level networking interface](https://docs.python.org/3/library/socket.html)
- [How to Check if a Host is Reachable using Python - Best Methods](https://copyprogramming.com/howto/how-to-check-if-a-host-is-reachable-using-python-best-methods)
- [Let's! Ping The Network with 15 Line Of Code Using Python & Scapy!](https://dev.to/powerexploit/let-s-ping-the-network-with-python-scapy-5g18)
- [Windows Sockets Error Codes](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2)
- [Port Scanner using Python](https://www.geeksforgeeks.org/port-scanner-using-python/)
- [SYN Stealth Scan with Power of Python Scapy](https://dev.to/powerexploit/syn-stealth-scan-with-power-of-python-scapy-58aj)
- [Python Penetration Testing - Port Scanning](https://www.oreilly.com/library/view/python-penetration-testing/9781789138962/9f389f41-4489-4628-a61f-969eea3aae8c.xhtml)
- [Port Scanning using Scapy](https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/)

## Contributors

- [Thu Tran](https://github.com/thuntran) (I worked independently on this final project.)
