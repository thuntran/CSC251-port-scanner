import socket
import argparse
import time
import datetime
import pytz
import random
import select
from scapy.all import *
from scapy.all import IP, TCP, ICMP


def is_host_alive(target_host):
    """
    Checks if a target host is alive by sending an ICMP packet (ICMP ping).

    Args:
        target_host (str): the IP address of the target host

    Returns:
        tuple[bool, float]: a tuple with a boolean indicating whether the host is alive
        and the latency for the host to be up, measured in seconds

    """
    is_alive = False

    # Start latency timer
    latency_start_time = time.time()

    # Reference: https://dev.to/powerexploit/let-s-ping-the-network-with-python-scapy-5g18

    # Construct an ICMP packet and send it to the target host
    icmp_packet_response = sr1(
        IP(dst=target_host) / ICMP(), timeout=10, verbose=0
    )

    # If there is a response, host is alive
    if icmp_packet_response:
        is_alive = True

    # End latency timer
    latency_end_time = time.time()

    # Calculate latency
    latency = latency_end_time - latency_start_time

    return is_alive, latency


def normal_scan(target_host, ports):
    """
    Performs a TCP full connect scan on a target host.

    Args:
        target_host (str): the IP address of the target host
        ports (list): a list of ports to scan

    Returns:
        A tuple containing the number of closed ports and a list of tuples
        containing the open ports and their corresponding services.

    """
    closed_ports, open_ports = 0, []
    src_port = RandShort()
    print()

    for port in ports:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)

        # Try establishing a connection to the target host at the specified IP address and port number
        try:
            s.connect((target_host, port))
        # If the connection is unsuccessful, the port is assumed to be closed
        except:
            closed_ports += 1
            s.close()
            continue

        # Reference: https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/

        # Construct a TCP SYN packet and send it to the target host
        syn_packet_response = sr1(
            IP(dst=target_host) / TCP(sport=src_port, dport=port, flags="S"),
            timeout=1,
            verbose=0,
        )

        # If there is no response, the port is closed
        if not syn_packet_response:
            closed_ports += 1

        # If there is a response, check the TCP flags to determine whether the port is open or closed
        elif syn_packet_response.haslayer(TCP):
            # If the TCP SYN/ACK flag is set, the port is open
            if syn_packet_response.getlayer(TCP).flags == 0x12:  # "SA"
                # Construct a TCP ACK/RST packet and send it to the target host to complete the 3-way handshake
                ack_rst_packet = sr(
                    IP(dst=target_host)
                    / TCP(sport=src_port, dport=port, flags="AR"),
                    timeout=1,
                    verbose=0,
                )

                # Get the name of the service running on the open port
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"

                # Add the open port to the list of open ports
                open_ports.append((port, service))

                # Grab the banner message from the service
                # Reference: https://stackoverflow.com/questions/2719017/how-to-set-timeout-on-pythons-socket-recv-method
                s.setblocking(0)
                ready = select.select([s], [], [], 1)
                if ready[0]:
                    banner = s.recv(1024)
                else:
                    banner = None
                print(f"Port {port} ({service}) is open: {banner}")

            # If the TCP ACK/RST flag is set, the port is closed
            elif syn_packet_response.getlayer(TCP).flags == 0x14:  # "AR"
                closed_ports += 1

        # Close the socket
        s.close()

    print()
    return closed_ports, open_ports


def syn_scan(target_host, ports):
    """
    Performs a TCP SYN scan on a target host.

    Args:
        target_host (str): the IP address of the target host
        ports (list): a list of ports to scan

    Returns:
        A tuple containing the number of closed ports and a list of tuples
        containing the open ports and their corresponding services.

    """

    closed_ports, open_ports = 0, []
    src_port = RandShort()
    print()

    for port in ports:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)

        # Try establishing a connection to the target host at the specified IP address and port number
        try:
            s.connect((target_host, port))
        # If the connection is unsuccessful, the port is assumed to be closed
        except:
            closed_ports += 1
            s.close()
            continue

        # Reference: https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/

        # Construct a TCP SYN packet and send it to the target host
        syn_packet_response = sr1(
            IP(dst=target_host) / TCP(sport=src_port, dport=port, flags="S"),
            timeout=1,
            verbose=0,
        )

        # If there is no response, the port is filtered
        if not syn_packet_response:
            # Get the name of the service running on the filtered port
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            print(f"Port {port} ({service}) is filtered")
            continue

        # If a response was received, check the TCP SYN/ACK flag to determine whether the port is open or closed
        elif syn_packet_response.haslayer(TCP):
            # If the TCP SYN/ACK flag is set
            if syn_packet_response.getlayer(TCP).flags == 0x12:  # "SA"
                # Construct a TCP RST packet and send it to the target host
                rst_packet = sr(
                    IP(dst=target_host)
                    / TCP(sport=src_port, dport=port, flags="R"),
                    timeout=1,
                    verbose=0,
                )

                # Get the name of the service running on the open port
                try:
                    service = socket.getservbyport(port)
                except OSError:
                    service = "unknown"
                # Add the open port to the list of open ports
                open_ports.append((port, service))
                print(f"Port {port} ({service}) is open")

            # If the TCP ACK/RST flag is set, the port is closed
            elif syn_packet_response.getlayer(TCP).flags == 0x14:  # "AR"
                closed_ports += 1

        # Close the socket
        s.close()

    print()
    return closed_ports, open_ports


def fin_scan(target_host, ports):
    """
    Performs a TCP FIN scan on a target host.

    Args:
        target_host (str): the IP address of the target host
        ports (list): a list of ports to scan

    Returns:
        A tuple containing the number of closed ports and a list of tuples
        containing the open ports and their corresponding services.

    """
    closed_ports, open_ports = 0, []
    print()

    for port in ports:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.01)

        # Try establishing a connection to the target host at the specified IP address and port number
        try:
            s.connect((target_host, port))
        # If the connection is unsuccessful, the port is assumed to be closed
        except:
            closed_ports += 1
            s.close()
            continue

        # Reference: https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/

        # Construct a TCP FIN packet and send it to the target host
        fin_packet_response = sr1(
            IP(dst=target_host) / TCP(dport=port, flags="F"),
            timeout=0.1,
            verbose=0,
        )

        # If there is no response, the port is open or filtered
        if not fin_packet_response:
            # Get the name of the service running on the open|filtered port
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"
            # Add the open port to the list of open ports
            open_ports.append((port, service))
            print(f"Port {port} ({service}) is open|filtered")

        # If there is a response with the TCP ACK/RST flag set, the port is closed
        elif fin_packet_response.haslayer(TCP):
            if fin_packet_response.getlayer(TCP).flags == 0x14:  # "AR"
                closed_ports += 1

        # Close the socket
        s.close()

    print()
    return closed_ports, open_ports


def port_scan(target_host, mode, order, ports):
    """
    Performs a port scan on the target host based on the options set by the user.

    Args:
        target_host: the IP address of the target host
        mode: the type of port scan to perform (must be one of "normal", "syn", or "fin")
        order: the order in which to scan the ports (must be one of "order" or "random")
        ports: the range of ports to scan (must be one of "all" or "known")

    Returns:
        None.

    """
    # Start the timer
    start_time = time.time()

    # Initialize a variable to keep track of the number of alive hosts
    # Since this program is meant to scan only 1 target host, alive_host_count is either 0 or 1
    alive_host_count = 0

    current_time = datetime.now(pytz.timezone("US/Eastern"))
    current_time = str(current_time.strftime("%Y-%m-%d %H:%M:%S %Z"))
    print(f"Starting port scan at \033[1m{current_time}\033[0m")

    try:
        target_hostname = socket.gethostbyaddr(target_host)[0]
        print(
            f"Port scan report for \033[1m{target_hostname} ({target_host})\033[0m"
        )

        # Check if the target host is alive
        host_alive, latency = is_host_alive(target_host)
        if host_alive:
            print(f"Host is up ({latency:.4f}s latency).")
            alive_host_count += 1
        else:
            print("Host is down. Please try again.")
            return  # Exit scan if host is down

        closed_ports, open_ports = 0, []

        ### START OF SCAN
        if ports == "all":
            if order == "order":
                if mode == "normal":
                    closed_ports, open_ports = normal_scan(
                        target_host, range(0, 65536)
                    )
                elif mode == "syn":
                    closed_ports, open_ports = syn_scan(
                        target_host, range(0, 65536)
                    )
                else:  # mode == "fin":
                    closed_ports, open_ports = fin_scan(
                        target_host, range(0, 65536)
                    )

            else:  # order == "random":
                if mode == "normal":
                    closed_ports, open_ports = normal_scan(
                        target_host, random.sample(range(0, 65536), 65536)
                    )
                elif mode == "syn":
                    closed_ports, open_ports = syn_scan(
                        target_host, random.sample(range(0, 65536), 65536)
                    )
                else:  # mode == "fin":
                    closed_ports, open_ports = fin_scan(
                        target_host, random.sample(range(0, 65536), 65536)
                    )
                open_ports = sorted(open_ports, key=lambda x: x[0])

        else:  # ports == "known":
            if order == "order":
                if mode == "normal":
                    closed_ports, open_ports = normal_scan(
                        target_host, range(0, 1024)
                    )
                elif mode == "syn":
                    closed_ports, open_ports = syn_scan(
                        target_host, range(0, 1024)
                    )
                else:  # mode == "fin":
                    closed_ports, open_ports = fin_scan(
                        target_host, range(0, 1024)
                    )

            else:  # order == "random":
                if mode == "normal":
                    closed_ports, open_ports = normal_scan(
                        target_host, random.sample(range(0, 1024), 1024)
                    )
                elif mode == "syn":
                    closed_ports, open_ports = syn_scan(
                        target_host, random.sample(range(0, 1024), 1024)
                    )
                else:  # mode == "fin":
                    closed_ports, open_ports = fin_scan(
                        target_host, random.sample(range(0, 1024), 1024)
                    )
                open_ports = sorted(open_ports, key=lambda x: x[0])
        ### END OF SCAN

        # Show the number of closed ports
        print(f"\033[4m\033[1mNot shown:\033[0m {closed_ports} closed port(s)")

        # Show the open port(s)/state(s)/service(s)
        print("\033[1mPORT      STATE SERVICE\033[0m")
        for port, service in open_ports:
            port_spacing = (10 - len(str(port) + "/tcp")) * " "
            print(
                f"\033[0;32m{f'{port}/tcp{port_spacing}'}{'open'}  {service}\033[0m"
            )

        print()
    except socket.gaierror:
        print(f'Failed to resolve "{target_host}"')
        print(
            f"\033[4m\033[1mWARNING:\033[0m No targets were specified, so {alive_host_count} hosts scanned"
        )

    # Stop the timer
    end_time = time.time()

    # Calculate the time taken for the scan
    duration = end_time - start_time

    address_word, host_word = "address", "host"
    if alive_host_count == 0:
        address_word += "es"
        host_word += "s"
    print(
        f"\033[4m\033[1mScan done:\033[0m {alive_host_count} IP {address_word} ({alive_host_count} {host_word} up) scanned in {duration:.2f} seconds"
    )


def main():
    # Define parser
    parser = argparse.ArgumentParser(description="Port scanner")

    # Add arguments to the parser
    parser.add_argument(
        "-mode",
        choices=["normal", "syn", "fin"],
        default="normal",
        help="Scanning mode (default scanning mode is normal)",
    )
    parser.add_argument(
        "-order",
        choices=["order", "random"],
        default="order",
        help="Scanning order (default scanning order is order)",
    )
    parser.add_argument(
        "-ports",
        choices=["all", "known"],
        default="all",
        help="Ports to scan (default range of ports is all)",
    )
    parser.add_argument("-target_ip", help="Target IP address")
    args = parser.parse_args()

    # Extract the arguments from argparse
    target_ip = args.target_ip
    mode = args.mode
    order = args.order
    ports = args.ports

    # Conduct port scan
    port_scan(target_ip, mode, order, ports)


if __name__ == "__main__":
    main()
