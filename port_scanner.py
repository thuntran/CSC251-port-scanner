import socket
import argparse
import time
import datetime
import pytz
import random
from scapy.all import sr, sr1, send, IP, TCP, ICMP


def is_host_alive(target_host):
    """Checks if a target host is alive by sending an ICMP packet (ICMP ping).

    Args:
        target_host (str): the IP address of the target host

    Returns:
        tuple[bool, float]: a tuple with a boolean indicating whether the host is alive
        and the measured latency in seconds
    """
    is_alive = False

    # Start latency timer
    latency_start_time = time.time()

    # Send an ICMP packet and wait for a response
    icmp_packet = IP(dst=target_host) / ICMP()
    icmp_packet_response = sr1(icmp_packet, timeout=10, verbose=0)
    if icmp_packet_response:
        is_alive = True  # Host is alive

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
    print()

    for port in ports:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target_host, port))

        # If the connection attempt was successful
        if result == 0:
            # Construct a TCP SYN packet and send it to the target host
            syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
            syn_packet_response = sr1(syn_packet, timeout=1, verbose=0)

            # If no response was received, the port is assumed to be closed
            if not syn_packet_response:
                closed_ports += 1

            # If a response was received, check the TCP flags to determine whether
            # the port is open or closed
            elif syn_packet_response.haslayer(TCP):
                if syn_packet_response.getlayer(TCP).flags == 0x12:
                    # Construct a TCP ACK/RST packet and send it to the target host
                    send_rst = sr(
                        IP(dst=target_host) / TCP(dport=port, flags="AR"),
                        timeout=1,
                        verbose=0,
                    )
                    # Get the name of the service running on the open port
                    service = socket.getservbyport(port)
                    # Add the open port to the list of open ports
                    open_ports.append((port, service))
                    # Grab the banner message from the service
                    banner = s.recv(1024)
                    print(f"Port {port} ({service}) is open: {banner}")

                elif syn_packet_response.getlayer(TCP).flags == 0x14:
                    # If the TCP RST/ACK flag is set, the port is closed
                    closed_ports += 1

                    closed_ports += 1
        # If the connection attempt was unsuccessful, the port is assumed to be closed
        else:
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
    print()

    for port in ports:
        # Create a TCP socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target_host, port))

        # If connection is successful, send a SYN packet and wait for response
        if result == 0:
            syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
            syn_packet_response = sr1(syn_packet, timeout=1, verbose=0)

            # If response contains a TCP layer, check SYN-ACK flag
            if syn_packet_response.haslayer(TCP):
                if syn_packet_response.getlayer(TCP).flags == "SA":
                    service = socket.getservbyport(port)
                    open_ports.append((port, service))
                    print(f"Port {port} ({service}) is open")

                    # Send RST packet to client
                    client_ip = syn_packet_response[IP].src
                    client_port = syn_packet_response[TCP].sport
                    rst_packet = IP(dst=client_ip) / TCP(
                        dport=client_port, sport=port, flags="R"
                    )
                    send(rst_packet, verbose=0)
        else:
            closed_ports += 1

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
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target_host, port))

        if result == 0:
            # If the connection is successful, send a FIN packet to the port
            fin_packet = IP(dst=target_host) / TCP(dport=port, flags="F")
            fin_packet_response = sr1(fin_packet, timeout=1, verbose=0)

            # If the port is open, the host will send a RST packet in response to the FIN packet
            # If the port is closed or filtered, no response will be received
            if not fin_packet_response:
                service = socket.getservbyport(port)
                open_ports.append((port, service))
                print(f"Port {port} ({service}) is open")
            elif fin_packet_response.haslayer(TCP):
                if fin_packet_response.getlayer(TCP).flags == 0x14:
                    closed_ports += 1
        else:
            closed_ports += 1

        s.close()

    print()
    return closed_ports, open_ports


def port_scan(target_host, mode, order, ports):
    """
    Perform a port scan on the target host, based on a user's options

    Args:
        target_host: the IP address of the target host
        mode: the type of port scan to perform. Must be one of "normal", "syn", or "fin".
        order: the order in which to scan the ports. Must be one of "order" or "random".
        ports: the range of ports to scan. Must be one of "all" or "known".

    Returns:
        None.


    The function performs a port scan on the specified target host using the specified mode,
    order, and range of ports. The scan results are printed to the console.

    The function first checks if the target host is alive, and then scans the specified range
    of ports using the specified mode and order. The results are printed to the console, showing
    the open ports, their states, and services.

    If the target host is not alive or cannot be resolved, a warning message is printed to
    the console.

    The function also prints the duration of the scan and the number of IP addresses and hosts
    scanned.
    """
    # Start the timer
    start_time = time.time()

    alive_host_count = 0

    current_time = datetime.datetime.now(pytz.timezone("US/Eastern"))
    print(
        "Starting port scan at \033[1m"
        + str(current_time.strftime("%Y-%m-%d %H:%M:%S %Z"))
        + "\033[0m"
    )

    try:
        target_hostname = socket.gethostbyaddr(target_host)[0]
        print(
            "Port scan report for \033[1m"
            + target_hostname
            + " ("
            + target_host
            + ")\033[0m"
        )

        # First, check if the target host is alive
        host_alive, latency = is_host_alive(target_host)
        if host_alive:
            print(f"Host is up ({latency:.4f}s latency).")
        else:
            print("Host is down. Please try again.")
            return

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
        ### END OF SCAN

        # Show the number of closed ports
        print(
            "\033[4m\033[1mNot shown:\033[0m "
            + str(closed_ports)
            + " closed port(s)"
        )

        # Show the open port(s)/state(s)/service(s)
        print("\033[1mPORT    STATE SERVICE\033[0m")
        for port, service in open_ports:
            port_spacing = (8 - len(str(port) + "/tcp")) * " "
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
    parser.add_argument("target_ip", help="Target IP address")
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
