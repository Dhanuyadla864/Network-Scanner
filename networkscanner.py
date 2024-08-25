from scapy.all import ICMP, IP, sr1, sr, conf
import ipaddress

# Disable scapy's warnings
conf.verb = 0

def scan_network(network):
    # Convert network to an IPv4Network object
    net = ipaddress.ip_network(network, strict=False)
    
    # List to store live hosts
    live_hosts = []

    for ip in net.hosts():
        response = sr1(IP(dst=str(ip))/ICMP(), timeout=1, verbose=False)
        if response is not None and response.haslayer(ICMP):
            if response.getlayer(ICMP).type == 0:  # ICMP Echo Reply
                live_hosts.append(str(ip))
    
    return live_hosts

def main():
    # Define the network to scan
    network = "192.168.1.0/24"  # Change this to match your network range
    print(f"Scanning network: {network}")
    
    # Perform the scan
    live_hosts = scan_network(network)
    
    # Print live hosts
    if live_hosts:
        print("Live hosts found:")
        for host in live_hosts:
            print(host)
    else:
        print("No live hosts found.")

if __name__ == "__main__":
    main()
