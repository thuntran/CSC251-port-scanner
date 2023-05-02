import socket
import argparse
import time
import datetime
import pytz
import random
from scapy.all import *
from scapy.all import IP, TCP


# TODO: Write docstrings for each function. Complete README. Check check check!
def is_host_alive(host):
    try:
        # Stop the timer
        latency_start_time = time.time()
        socket.gethostbyname(host)
        latency_end_time = time.time()
        latency_duration = latency_end_time - latency_start_time
        return True, latency_duration
    except:
        return False, 0


def normal_scan(target_host, ports):
    closed_ports, open_ports = 0, []
    print()

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target_host, port))

        if result == 0:
            syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
            syn_packet_response = sr1(syn_packet, timeout=1, verbose=0)
            if not syn_packet_response:
                closed_ports += 1
            elif syn_packet_response.haslayer(TCP):
                if syn_packet_response.getlayer(TCP).flags == 0x12:
                    send_rst = sr(
                        IP(dst=target_host) / TCP(dport=port, flags="AR"),
                        timeout=1,
                        verbose=0,
                    )
                    service = socket.getservbyport(port)
                    open_ports.append((port, service))
                    banner = s.recv(1024)
                    print(f"Port {port} ({service}) is open: {banner}")
                elif syn_packet_response.getlayer(TCP).flags == 0x14:
                    closed_ports += 1
        else:
            closed_ports += 1

        s.close()

    print()
    return closed_ports, open_ports


def syn_scan(target_host, ports):
    closed_ports, open_ports = 0, []
    print()

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target_host, port))

        if result == 0:
            syn_packet = IP(dst=target_host) / TCP(dport=port, flags="S")
            syn_packet_response = sr1(syn_packet, timeout=1, verbose=0)
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
    closed_ports, open_ports = 0, []
    print()
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        result = s.connect_ex((target_host, port))

        if result == 0:
            fin_packet = IP(dst=target_host) / TCP(dport=port, flags="F")
            fin_packet_response = sr1(fin_packet, timeout=1, verbose=0)
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
    # Start the timer
    start_time = time.time()

    current_time = datetime.now(pytz.timezone("US/Eastern"))

    print(
        "Starting port scan at \033[1m"
        + str(current_time.strftime("%Y-%m-%d %H:%M:%S %Z"))
        + "\033[0m"
    )
    print("Port scan report for \033[1m" + target_host + "\033[0m")

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

    # Stop the timer
    end_time = time.time()

    # Calculate the time taken for the scan
    duration = end_time - start_time

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
    print(
        f"\033[4m\033[1mScan done:\033[0m 1 IP address (1 host up) scanned in {duration:.2f} seconds"
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

    target_hostname = input("Enter host name: ")
    host_alive, latency = is_host_alive(target_hostname)
    if host_alive:
        print(f"Host is up ({latency:.4f}s latency).")  # TODO: if possible, implement to show latency
        port_scan(target_ip, mode, order, ports)
    else:
        print("Host is not alive or invalid. Please try again.")


if __name__ == "__main__":
    main()
