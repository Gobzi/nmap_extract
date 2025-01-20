import os
import re
import sys
from xml.etree import ElementTree as ET

def process_gnmap(file_path):
    results = []
    with open(file_path, 'r') as file:
        for line in file:
            if "Host:" in line:
                ip_match = re.search(r"Host: ([\d.]+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    ports = re.findall(r"(\d+)\/(tcp|udp)\/open", line)
                    for port, protocol in ports:
                        results.append(f"{ip} -> Open Port: {port} ({protocol})")
    return results
    
def process_nmap(file_path):
    results = []
    ip = None
    with open(file_path, 'r') as file:
        for line in file:
            if line.startswith("Nmap scan report for"):
                ip = line.split()[-1]
            elif "open" in line and ip:
                port_match = re.search(r"(\d+)\/(tcp|udp)", line)
                if port_match:
                    port, protocol = port_match.groups()
                    results.append(f"{ip} -> Open Port: {port} ({protocol})")
    return results
    
def process_xml(file_path):
    results = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        for host in root.findall(".//host"):
            ip = host.find(".//address[@addrtype='ipv4']")
            if ip is not None:
                ip = ip.attrib['addr']
                for port in host.findall(".//port[@state='open']"):
                    protocol = port.attrib['protocol']
                    port_id = port.attrib['portid']
                    results.append(f"{ip} -> Open Port: {port_id} ({protocol})")
    except ET.ParseError as e:
        print(f"Error parsing XML file {file_path}: {e}")
    return results


def main(extension):
    files = [f for f in os.listdir('.') if f.endswith(f".{extension}")]
    if not files:
        print(f"No files with extension '.{extension}' found.")
        return

    print(f"Processing all '.{extension}' files in the current directory...")
    print("=" * 60)

    for file in files:
        print(f"Processing file: {file}")
        print("-" * 60)

        if extension == "gnmap":
            results = process_gnmap(file)
        elif extension == "nmap":
            results = process_nmap(file)
        elif extension == "xml":
            results = process_xml(file)
        else:
            print(f"Unsupported file extension: {extension}")
            continue

        if results:
            print("\n".join(results))
        else:
            print(f"No open ports found in {file}.")

        print("-" * 60)

    print("Processing complete.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python extract_open_ports.py <extension>")
        print("Example: python extract_open_ports.py gnmap")
        sys.exit(1)

    extension = sys.argv[1]
    main(extension)
