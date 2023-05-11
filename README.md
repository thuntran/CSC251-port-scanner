# Port Scanner

## Necessary files

The only file required to run this port scanner is `port_scanner.py`.

## Instructions

### Installing necessary modules

- Install the `scapy` module for packet manipulation:

  ```bash
  pip install scapy
  ```

- Install the `pytz` module to view the timezone shown in the port scanner output:

  ```bash
  pip install pytz
  ```

- Other than that, the remaining modules used in this program are pre-installed in Python, and do not need to be installed using `pip`.

### Running the port scanner

- To run the port scanner, from the terminal (MacOS/Linux) or command prompt (Windows):

  ```bash
  python3 port_scanner.py -mode [normal/syn/fin] -order [order/random] -ports [all/known] -target_ip [ip_address]
  ```

- Notes about testing the port scanner:

  - The IP address of the target host to be tested on is **131.229.72.13**.
  - The target hostname is **glasgow.smith.edu**.
  - Order of the arguments does not matter. However, it is important to include the corresponding flags (`-mode`, `-order`, `-ports`, `-target_ip`) in front of the arguments, like what is demonstrated in the command line above.
  - Doing multiple rounds of testing at once might cause the host to be down (`WARNING: Mac address to reach destination not found. Using broadcast.`). A suggestion is to wait a bit and then run the port scanner again.
  - **IMPORTANT: This port scanner is only intended to scan the host specified above. It is important that the port scanner should not be misused (i.e. to scan other hosts without permission.)**

- Expected results:

  - Here is an example of what the output looks like when running the port scanner on a valid host:

  ```bash
  python3 port_scanner.py -mode syn -order order -ports known 131.229.72.13
  ```

  ```
  Starting port scan at 2023-05-10 09:50:42 EDT
  Port scan report for glasgow.smith.edu (131.229.72.13)
  Host is up (0.0160s latency).

  Port 21 (ftp) is open
  Port 22 (ssh) is open
  Port 80 (http) is open
  Port 443 (https) is open

  Not shown: 1020 closed port(s)
  PORT      STATE SERVICE
  21/tcp    open  ftp
  22/tcp    open  ssh
  80/tcp    open  http
  443/tcp   open  https
  ```

  - Additionally, here is an example of what the output looks like when running the port scanner on an invalid host:

  ```bash
  python3 port_scanner.py -mode syn -order random -ports known 131.229.72.1300000
  ```

  ```
  Starting port scan at 2023-05-10 09:59:33 EDT
  Failed to resolve "131.229.72.1300000"
  WARNING: No targets were specified, so 0 hosts scanned
  Scan done: 0 IP addresses (0 hosts up) scanned in 0.08 second
  ```

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
- [TCP Connect Scan (-sT)](https://nmap.org/book/scan-methods-connect-scan.html)
- [TCP SYN (Stealth) Scan (-sS)](https://nmap.org/book/synscan.html#:~:text=SYN%20scan%20is%20the%20default,not%20hampered%20by%20intrusive%20firewalls.)
- [TCP FIN, NULL, and Xmas Scans (-sF, -sN, -sX)](https://nmap.org/book/scan-methods-null-fin-xmas-scan.html)
- [How to Set Timeout on Python's socket recv Method?](https://stackoverflow.com/questions/2719017/how-to-set-timeout-on-pythons-socket-recv-method)
- [Add Colour to Text in Python](https://ozzmaker.com/add-colour-to-text-in-python/)

## Contributors

- [Thu Tran](https://github.com/thuntran) (I worked independently on this final project.)
