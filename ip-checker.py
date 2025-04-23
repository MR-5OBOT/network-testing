import socket
import time

# ANSI escape codes for colored output
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"


def resolve_host(host):
    """Resolve a domain name or IP to an IP address."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as e:
        print(RED + f"[-] DNS Resolution Error: {e}" + RESET)
        return None


def check_tcp_port(ip, port):
    """Check if a TCP port is open on the given IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0


def check_udp_port(ip, port):
    """Check if a UDP port is open on the given IP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1)
    try:
        sock.sendto(b"test", (ip, port))
        sock.recvfrom(1024)
        return True
    except socket.timeout:
        return True
    except socket.error:
        return False
    finally:
        sock.close()


def get_ports():
    """Return a list of ports with their descriptions and protocols."""
    return [
        # TCP Ports from Original List
        (21, "FTP (Control)", "TCP"),
        (22, "SSH", "TCP"),
        (80, "HTTP", "TCP"),
        (443, "HTTPS", "TCP"),
        (1080, "SOCKS Proxy", "TCP"),
        (4444, "Metasploit Payload", "TCP"),
        (8080, "HTTP-Alt (Proxy)", "TCP"),
        (9050, "Tor Proxy", "TCP"),
        (31337, "Backdoor (Elite)", "TCP"),
        # UDP Ports from Original List
        (53, "DNS (UDP)", "UDP"),
        (69, "TFTP", "UDP"),
        # VPN and Tunneling Ports (TCP and UDP)
        (1194, "OpenVPN (TCP)", "TCP"),
        (1194, "OpenVPN (UDP)", "UDP"),
        (500, "IPSec VPN (ISAKMP)", "UDP"),
        (4500, "IPSec NAT Traversal", "UDP"),
        (1701, "L2TP (VPN)", "UDP"),
        (1723, "PPTP VPN", "TCP"),
        # Additional Ports for VPN/Tunneling
        (53, "DNS (TCP)", "TCP"),
        (123, "NTP (Time Sync)", "UDP"),
        (143, "IMAP (Email)", "TCP"),
        (445, "SMB (File Sharing)", "TCP"),
        (993, "IMAPS (Secure Email)", "TCP"),
        (3478, "STUN (VoIP/Gaming)", "UDP"),
        (5060, "SIP (VoIP)", "UDP"),
        (10000, "Webmin (Admin)", "TCP"),
        (51820, "WireGuard (VPN)", "UDP"),
        (8388, "Shadowsocks (Proxy)", "TCP"),
        (8388, "Shadowsocks (Proxy)", "UDP"),
        # WebSocket Ports
        (80, "WebSocket (ws://)", "TCP"),
        (443, "WebSocket (wss://)", "TCP"),
        (8443, "WebSocket (Secure Alt)", "TCP"),
        (3000, "WebSocket (Dev)", "TCP"),
        (9000, "WebSocket (Custom)", "TCP"),
    ]


def print_banner():
    """Print a stylized hacker banner with MR5OBOT."""
    banner = """
    MR5OBOT PORT SCANNER
    """
    print(RED + banner + RESET)


def port_scanner(host):
    """Scan TCP and UDP ports on the given host and print styled results."""
    ip = resolve_host(host)
    if not ip:
        print(RED + f"[-] Error: Could not resolve '{host}'" + RESET)
        return

    print(f"\n[+] Target: {host} ({ip})")
    print(f"[+] Scanning ports for: {ip}")

    ports = get_ports()
    open_ports = []
    for port, service, protocol in ports:
        if protocol == "TCP":
            if check_tcp_port(ip, port):
                open_ports.append((port, protocol, service))
                print(GREEN + f"[+] Port {port} OPEN ({service}) [{protocol}]" + RESET)
            else:
                print(f"[-] Port {port} CLOSED ({service}) [{protocol}]")
        elif protocol == "UDP":
            if check_udp_port(ip, port):
                open_ports.append((port, protocol, service))
                print(GREEN + f"[+] Port {port} OPEN? ({service}) [{protocol}]" + RESET)
            else:
                print(f"[-] Port {port} CLOSED ({service}) [{protocol}]")
        time.sleep(0.1)

    # Formatted summary
    print(f"\n[+] Scan complete. Found {len(open_ports)} open port(s):")
    if open_ports:
        # Print a table header
        print(f"{'Port':<8} {'Protocol':<10} {'Service':<20}")
        print("-" * 38)  # Separator line
        # Print each open port in a formatted row
        for port, proto, service in open_ports:
            print(f"{port:<8} {proto:<10} {service:<20}")
    else:
        print("None")


def main():
    """Main function to run the port scanner."""
    print_banner()
    try:
        host = input("Enter target domain (e.g., example.com): ").strip()
        if not host:
            print(RED + "[-] Error: No input provided." + RESET)
            return
    except KeyboardInterrupt:
        print(RED + "\n[-] Exiting..." + RESET)
        return

    port_scanner(host)


if __name__ == "__main__":
    main()
