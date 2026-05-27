import argparse
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

# Common port fallback mapping if a banner can't be grabbed
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 443: "HTTPS",
    445: "SMB", 1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

# Thread-safe collections for tracking results
discovered_ports = []
final_results = {}

def check_port_status(target, port, timeout):
    """Stage 1: Fast connection check to see if port is open."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
        if result == 0:
            discovered_ports.append(port)
        s.close()
    except:
        pass

def grab_service_details(target, port):
    """Stage 2: Deep probe on discovered open ports for versions/banners."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)  # Slightly longer timeout to allow banners to load
        s.connect((target, port))
        
        # Send a generic request payload for client-silent protocols (like HTTP)
        if port in [80, 443, 8080, 8443]:
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        if banner:
            # Clean up formatting whitespace/newlines
            cleaned_banner = banner.replace('\n', ' ').replace('\r', '')[:60]
            final_results[port] = cleaned_banner
            return
    except:
        pass
    
    # Fallback to standard operating system service resolution
    try:
        final_results[port] = socket.getservbyport(port)
    except:
        final_results[port] = COMMON_SERVICES.get(port, "Unknown Service (No Banner)")

def main():
    parser = argparse.ArgumentParser(description="Two-Stage All-Port Service & Version Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-65535", help="Ports to scan. Default is ALL (1-65535)")
    parser.add_argument("-w", "--threads", type=int, default=300, help="Number of concurrent threads (Default: 300)")
    parser.add_argument("--timeout", type=float, default=0.8, help="Connection timeout in seconds (Default: 0.8)")
    
    args = parser.parse_args()
    
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(f"[-] Error: Hostname {args.target} could not be resolved.")
        sys.exit(1)
        
    # Parse port range
    if '-' in args.ports:
        start, end = map(int, args.ports.split('-'))
        ports_to_scan = list(range(start, end + 1))
    elif ',' in args.ports:
        ports_to_scan = list(map(int, args.ports.split(',')))
    else:
        ports_to_scan = [int(args.ports)]

    print("-" * 65)
    print(f"Target Destination : {target_ip}")
    print(f"Scan Range         : {args.ports} (Total: {len(ports_to_scan)} ports)")
    print(f"Thread Pool Size   : {args.threads}")
    print(f"Scan Iteration Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 65)
    
    # STAGE 1: Discover open ports
    print("[*] Stage 1: Fast sweeping for open ports...")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for port in ports_to_scan:
            executor.submit(check_port_status, target_ip, port, args.timeout)
            
    discovered_ports.sort()
    
    if not discovered_ports:
        print("\n[-] Scan completed. No open ports were found within the specified range.")
        sys.exit(0)
        
    print(f"[+] Found {len(discovered_ports)} open ports. Moving to Stage 2.")
    
    # STAGE 2: Deep scan raw discovered ports for service/version details
    print("[*] Stage 2: Direct service and version fingerprinting...")
    with ThreadPoolExecutor(max_workers=len(discovered_ports)) as executor:
        for port in discovered_ports:
            executor.submit(grab_service_details, target_ip, port)

    # --- PRINT FINAL COMPREHENSIVE REPORT ---
    print("\n" + "-" * 65)
    print(f"{'PORT':<10}{'STATUS':<10}{'SERVICE / VERSION BANNER'}")
    print("-" * 65)
    
    for port in discovered_ports:
        service_info = final_results.get(port, "Unknown")
        print(f"{port:<10}{'OPEN':<10}{service_info}")
        
    # --- EASY COPY SECTION ---
    print("\n" + "=" * 65)
    print(" QUICK COPY SECTION (Raw Ports)")
    print("=" * 65)
    ports_str = ",".join(map(str, discovered_ports))
    print(ports_str)
    print("=" * 65)

if __name__ == "__main__":
    main()