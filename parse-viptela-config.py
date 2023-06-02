import re
import sys

protocol_mapping = {
    '1': 'ICMP',
    '2': 'IGMP',
    '6': 'TCP',
    '9': 'IGRP',
    '17': 'UDP',
    '47': 'GRE',
    '50': 'ESP',
    '51': 'AH',
    '58': 'ICMPv6',
    '88': 'EIGRP',
    '89': 'OSPF',
    '94': 'IPV6-Nonxt',
    '103': 'PIM',
    '112': 'VRRP',
    '115': 'L2TP',
    '121': 'SMP',
    '132': 'SCTP',
    '135': 'NBSS',
    '139': 'NetBIOS',
    '143': 'IMAP',
    '161': 'SNMP',
    '162': 'SNMP Trap',
    '179': 'BGP',
    '194': 'IRC',
    '213': 'IPX',
    '520': 'RIP',
    '636': 'LDAPS',
    '873': 'RSYNC',
    '989': 'FTPS Data',
    '990': 'FTPS Control',
    '992': 'TELNETS',
    '993': 'IMAPS',
    '994': 'IRCS',
    '995': 'POP3S',
    '1158': 'DB-lsp-disc',
    '1434': 'MS-SQL-M',
    '1701': 'L2F',
    '1812': 'RADIUS',
    '1813': 'RADIUS Accounting',
    '2049': 'NFS',
    '2181': 'ZooKeeper',
    '2379': 'etcd',
    '3389': 'RDP',
    '5060': 'SIP',
    '5061': 'SIPS',
    '5432': 'PostgreSQL',
    '5500': 'VNC',
    '5632': 'PCAnywhere',
    '5900': 'VNC',
    '5985': 'WinRM',
    '6379': 'Redis',
    '8000': 'HTTP Alt',
    '8080': 'HTTP Proxy',
    '8081': 'HTTP Alt Proxy',
    '8443': 'HTTPS Alt',
    '8883': 'MQTT SSL',
    '9090': 'Zeus Admin',
    '9200': 'Elasticsearch',
    '9418': 'Git',
    '27017': 'MongoDB',
    '50000': 'SAP Router',
}

port_mapping = {
    '20': 'FTP Data',
    '21': 'FTP Control',
    '22': 'SSH',
    '23': 'Telnet',
    '25': 'SMTP',
    '37': 'Time',
    '43': 'Whois',
    '53': 'DNS',
    '67': 'DHCP Server',
    '68': 'DHCP Client',
    '69': 'TFTP',
    '80': 'HTTP',
    '88': 'Kerberos',
    '110': 'POP3',
    '123': 'NTP',
    '137': 'NetBIOS Name',
    '138': 'NetBIOS Datagram',
    '139': 'NetBIOS Session',
    '143': 'IMAP',
    '161': 'SNMP',
    '162': 'SNMP Trap',
    '179': 'BGP',
    '194': 'IRC',
    '389': 'LDAP',
    '443': 'HTTPS',
    '445': 'SMB',
    '465': 'SMTPS',
    '500': 'ISAKMP',
    '513': 'rlogin',
    '514': 'syslog',
    '515': 'LPD',
    '520': 'RIP',
    '554': 'RTSP',
    '587': 'SMTP (Submission)',
    '636': 'LDAPS',
    '873': 'rsync',
    '902': 'VMware Server',
    '989': 'FTPS Data',
    '990': 'FTPS Control',
    '992': 'TelnetS',
    '993': 'IMAPS',
    '995': 'POP3S',
    '1080': 'SOCKS',
    '1194': 'OpenVPN',
    '1433': 'MS-SQL',
    '1434': 'MS-SQL-M',
    '1701': 'L2TP',
    '1723': 'PPTP',
    '1812': 'RADIUS',
    '1813': 'RADIUS Accounting',
    '2049': 'NFS',
    '2222': 'SSH',
    '3128': 'Squid Proxy',
    '3306': 'MySQL',
    '3389': 'RDP',
    '3690': 'SVN',
    '4333': 'mSQL',
    '4500': 'IPSec NAT-T',
    '4700': 'NetXMS',
    '5060': 'SIP',
    '5222': 'XMPP',
    '5432': 'PostgreSQL',
    '5500': 'VNC',
    '5632': 'PCAnywhere',
    '5900': 'VNC',
    '5985': 'WinRM',
    '6379': 'Redis',
    '8080': 'HTTP (Proxy)',
    '8443': 'HTTPS (Alt)',
    '8888': 'HTTP (Alt)',
    '8883': 'MQTT SSL',
    '9000': 'Elasticsearch',
    '9001': 'etcd',
    '9090': 'Zeus Admin',
    '9200': 'Elasticsearch',
    '9418': 'Git',
    '27017': 'MongoDB',
    '50000': 'SAP Router',
}


def get_protocol(protocol):
    protocols = protocol.split()
    mapped_protocols = []
    for p in protocols:
        mapped_protocol = protocol_mapping.get(p, p)
        mapped_protocols.append(mapped_protocol)
    return ' '.join(mapped_protocols)

def get_port(port):
    port_ranges = port.split()
    labels = []
    for port_range in port_ranges:
        if '-' in port_range:
            start, end = port_range.split('-')
            start_label = port_mapping.get(start.strip(), start.strip())
            end_label = port_mapping.get(end.strip(), end.strip())
            labels.append(f"{start_label}-{end_label}")
        else:
            port_label = port_mapping.get(port_range.strip(), port_range.strip())
            labels.append(port_label)
    return ' '.join(labels)

def parse_text(text):
    result = []
    policy_pattern = r"zone-based-policy ([A-Za-z0-9_-]+)(.*?)!(?=\s*zone-based-policy|\Z)"
    matches = re.findall(policy_pattern, text, re.DOTALL)

    for match in matches:
        policy_name = match[0]
        policy_content = match[1]

        sequence_pattern = r"sequence (\d+)(.*?)!(?=\s*sequence|\Z)"
        sequence_matches = re.findall(sequence_pattern, policy_content, re.DOTALL)

        entries = []
        for sequence_match in sequence_matches:
            sequence_entry = {}
            sequence_entry["sequence"] = sequence_match[0]

            match_pattern = r"match(.*?)!(?=\s*action|\Z)"
            match_match = re.search(match_pattern, sequence_match[1], re.DOTALL)
            if match_match:
                match_content = match_match.group(1)

                ip_pattern = r"destination-ip\s+([A-Za-z0-9./ ]+)"
                ip_matches = re.findall(ip_pattern, match_content)
                if ip_matches:
                    sequence_entry["destination_ip"] = ', '.join(ip_matches)

                source_prefix_pattern = r"source-data-prefix-list\s+([A-Za-z0-9_]+)"
                source_prefix_match = re.search(source_prefix_pattern, match_content)
                if source_prefix_match:
                    sequence_entry["source_data_prefix_list"] = source_prefix_match.group(1)
                    
                dest_prefix_pattern = r"destination-data-prefix-list\s+([A-Za-z0-9_]+)"
                dest_prefix_match = re.search(dest_prefix_pattern, match_content)
                if dest_prefix_match:
                    sequence_entry["destination_data_prefix_list"] = dest_prefix_match.group(1)

                port_pattern = r"destination-port\s+([\d\s-]+)"
                port_match = re.search(port_pattern, match_content)
                if port_match:
                    sequence_entry["destination_port"] = get_port(port_match.group(1))

                protocol_pattern = r"protocol\s+([A-Za-z0-9 ]+)"
                protocol_matches = re.findall(protocol_pattern, match_content)
                if protocol_matches:
                    protocols = [get_protocol(p.strip()) for p in protocol_matches]
                    sequence_entry["protocol"] = ' '.join(protocols)

            action_pattern = r"action\s+(\w+)"
            action_match = re.search(action_pattern, sequence_match[1])
            if action_match:
                sequence_entry["action"] = action_match.group(1)

            entries.append(sequence_entry)

        policy_entry = {
            "label": policy_name.strip(),
            "sequences": entries
        }
        result.append(policy_entry)

    return result

# Read input from stdin
text = sys.stdin.read()

parsed_data = parse_text(text)

# Markdown Table Headers
headers = "| Sequence | Destination IP | Source Data Prefix List | Destination Data Prefix List | Destination Port | Protocol | Action |"
# Markdown Table Divider
divider = "| --- | --- | --- | --- | --- | --- | --- |"

prev_policy_name = None
for policy in parsed_data:
    policy_name = policy["label"]
    if prev_policy_name != policy_name:
        print(f"\n## {policy_name}")
        print(headers)
        print(divider)
        prev_policy_name = policy_name
    for sequence in policy["sequences"]:
        sequence_num = sequence["sequence"]
        destination_ip = sequence.get("destination_ip", "")
        source_data_prefix_list = sequence.get("source_data_prefix_list", "")
        destination_data_prefix_list = sequence.get("destination_data_prefix_list", "")
        destination_port = sequence.get("destination_port", "")
        protocol = sequence.get("protocol", "")
        action = sequence.get("action", "")
        entry = f"| {sequence_num} | {destination_ip} | {source_data_prefix_list} | {destination_data_prefix_list} | {destination_port} | {protocol} | {action} |"
        print(entry)
