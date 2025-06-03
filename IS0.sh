#!/bin/bash

# raj-is0 Network Vulnerability Discovery Project
# Made by Madan Raj (LinkedIn: https://www.linkedin.com/in/madan-raj-vadathya-14b2a8264/)

# ASCII Banner
echo "
  _____                _            _____  _____  ___  
 |  __ \     /\       | |          |_   _|/ ____|/ _ \ 
 | |__| |   /  \      | |  ______    | | | (___ | | | |
 |  _  /   / /\ \ _   | | |______|   | |  \___ \| | | |
 | | \ \  / ____ \ |__| |           _| |_ ____) | |_| |
 |_|  \_\/_/    \_\____/           |_____|_____/ \___/ 
                                                       
                                                       
"
echo "   R A J - I S 0"
echo "
           Network Vulnerability Discovery
"
echo "Made by Madan Raj (https://www.linkedin.com/in/madan-raj-vadathya-14b2a8264/)"
echo "------------------------------------------------------------------------"

# Function to check for required tools
check_tools() {
    local missing_tools=()
    command -v nmap >/dev/null 2>&1 || missing_tools+=("nmap")
    command -v netdiscover >/dev/null 2>&1 || missing_tools+=("netdiscover")

    if [ ${#missing_tools[@]} -gt 0 ]; then
        echo "Error: The following required tools are not installed: ${missing_tools[*]}"
        echo "Please install them using your package manager (e.g., sudo apt install nmap netdiscover)."
        exit 1
    fi
}

# Call the tool check function
check_tools

# Function to get network address from IP
get_network_address() {
    local ip=$1
    # Basic regex to validate IP format
    if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        echo "Invalid IP address format. Please enter a valid IPv4 address."
        exit 1
    fi
    # Assume /24 subnet for simplicity, common for local networks
    # For more robust subnet calculation, a dedicated tool or more complex script would be needed.
    local network=$(echo "$ip" | cut -d'.' -f1-3)".0/24"
    echo "$network"
}

# --- Main Script Logic ---

# 1. Ask for IP address
read -p "Enter the target IP address (e.g., 192.168.1.1): " target_ip

if [ -z "$target_ip" ]; then
    echo "IP address cannot be empty. Exiting."
    exit 1
fi

network_cidr=$(get_network_address "$target_ip")
echo "Target IP: $target_ip"
echo "Deduced Network CIDR: $network_cidr (assuming /24 subnet)"

# 2. Ask about live host details (netdiscover)
echo ""
read -p "Do you want to run netdiscover to find live hosts? (y/n): " run_netdiscover_choice

if [[ "$run_netdiscover_choice" =~ ^[Yy]$ ]]; then
    echo ""
    echo "Starting netdiscover in the background for 30 seconds to find live hosts."
    echo "Note: netdiscover often requires root privileges (sudo)."
    echo "If you want to run it in a separate, interactive terminal, open a new terminal and run: sudo netdiscover -r $network_cidr"
    echo "Capturing output for a short duration..."
    # Run netdiscover in the background for a short period and capture output
    sudo netdiscover -r "$network_cidr" -P -s 5 -c 10 > netdiscover_output.tmp 2>/dev/null &
    NETDISCOVER_PID=$!
    echo "netdiscover PID: $NETDISCOVER_PID (running in background)"
    echo "Waiting for netdiscover to gather some data (approx. 30 seconds)..."
    sleep 30
    kill $NETDISCOVER_PID 2>/dev/null
    echo "netdiscover stopped."
    echo ""
    echo "--- netdiscover output (partial) ---"
    cat netdiscover_output.tmp
    echo "------------------------------------"
    rm netdiscover_output.tmp
    echo ""
fi

# 3. Scan all IPs in the network for OS detection with nmap
echo "Scanning network ($network_cidr) for live hosts and OS detection with nmap..."
echo "This may take some time and requires root privileges (sudo)."

# Store discovered hosts in an associative array (IP:MAC:OS)
declare -A discovered_hosts
host_count=0

# Use grep and awk to parse nmap output
# -sn: Ping scan - disable port scan
# -O: OS detection
# -oG: Greppable output (easier to parse)
nmap_output=$(sudo nmap -sn -O -oG - "$network_cidr" 2>/dev/null)

echo "$nmap_output" | while IFS= read -r line; do
    if [[ "$line" =~ ^Host:\ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}).*Status:\ Up ]]; then
        ip=$(echo "$line" | awk -F' ' '{print $2}')
        mac=$(echo "$line" | grep -oP 'MAC Address: \K[^ ]+' | head -1)
        os_vendor=$(echo "$line" | grep -oP 'OS: \K[^;]+' | head -1)

        # Clean up OS/Vendor string
        if [ -z "$os_vendor" ]; then
            os_vendor="Unknown OS/Vendor"
        else
            # Remove parentheses and content within them, and any leading/trailing spaces
            os_vendor=$(echo "$os_vendor" | sed -E 's/\([^)]*\)//g' | sed -E 's/^\s+|\s+$//g')
        fi

        if [ -n "$ip" ]; then
            host_count=$((host_count + 1))
            discovered_hosts["$host_count"]="$ip:$mac:$os_vendor"
            echo "  $host_count) IP: $ip, MAC: ${mac:-N/A}, OS/Vendor: $os_vendor"
        fi
    fi
done

if [ "$host_count" -eq 0 ]; then
    echo "No live hosts found in the network $network_cidr."
    echo "Please ensure the target IP and network are correct, and nmap has sufficient permissions."
    exit 0
fi

echo ""
echo "------------------------------------------------------------------------"
echo "Discovered Hosts:"
# Re-list hosts for selection
for i in $(seq 1 $host_count); do
    IFS=':' read -r ip mac os_vendor <<< "${discovered_hosts[$i]}"
    echo "  $i) IP: $ip, MAC: ${mac:-N/A}, OS/Vendor: $os_vendor"
done
echo "  A) Scan ALL discovered hosts"
echo "------------------------------------------------------------------------"

# 4. User selects specific host or all
read -p "Enter the number of the host to scan, or 'A' for all: " selection

selected_ips=()

if [[ "$selection" =~ ^[Aa]$ ]]; then
    echo "You chose to scan ALL discovered hosts."
    for i in $(seq 1 $host_count); do
        IFS=':' read -r ip mac os_vendor <<< "${discovered_hosts[$i]}"
        selected_ips+=("$ip")
    done
elif [[ "$selection" =~ ^[0-9]+$ ]] && [ "$selection" -ge 1 ] && [ "$selection" -le "$host_count" ]; then
    IFS=':' read -r ip mac os_vendor <<< "${discovered_hosts[$selection]}"
    selected_ips+=("$ip")
    echo "You chose to scan host: $ip"
else
    echo "Invalid selection. Exiting."
    exit 1
fi

# 5. Perform detailed scan for selected hosts
echo ""
echo "Starting detailed nmap scans for selected host(s)."
echo "This will scan for open ports, service versions, OS details, and run default scripts."
echo "Each scan may take significant time and requires root privileges (sudo)."

for ip_to_scan in "${selected_ips[@]}"; do
    echo ""
    echo "------------------------------------------------------------------------"
    echo "Initiating comprehensive Nmap scan for: $ip_to_scan"
    echo "Command: sudo nmap -p- -sV -O -sC $ip_to_scan"
    echo "------------------------------------------------------------------------"

    # -p-: Scan all 65535 ports
    # -sV: Version detection
    # -O: OS detection
    # -sC: Run default Nmap scripts (useful for basic vulnerability checks)
    sudo nmap -p- -sV -O -sC "$ip_to_scan"

    echo "------------------------------------------------------------------------"
    echo "Scan for $ip_to_scan completed."
    echo "------------------------------------------------------------------------"
done

echo ""
echo "Project raj-is0 completed. Happy hunting!"
echo "Remember to analyze the scan results for potential vulnerabilities."
