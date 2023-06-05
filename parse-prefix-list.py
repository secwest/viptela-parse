import re
import socket
import ipaddress
import sys

def is_private_subnet(ip):
    return ipaddress.ip_network(ip).is_private

def get_dns_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ''

lines = sys.stdin.read().split('\n')
result = {}
start_processing = False

#print('Starting to process lines...', file=sys.stderr)  # Debug line

# parse data
for line in lines:
#    print(f'Processing line: {line}', file=sys.stderr)  # Debug line
    if 'data-prefix-list' in line:
        start_processing = True
        key = line.split()[-1]
        result[key] = []
    elif 'ip-prefix' in line and start_processing:
        ip = line.split()[-1]
        result[key].append(ip)

#print('Finished processing lines, starting to generate table...', file=sys.stderr)  # Debug line

# generate markdown table
md_table = 'List Name | Prefix | DNS Name\n--- | --- | ---\n'
for key, ips in result.items():
    for ip in ips:
        if '/32' in ip and not is_private_subnet(ip):
            dns_name = get_dns_name(ip.split('/')[0])
            md_table += f'{key} | {ip} | {dns_name}\n'
#    md_table += '\n'

print('Finished generating table, writing to stdout...', file=sys.stderr)  # Debug line

sys.stdout.write(md_table)
