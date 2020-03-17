from collections import defaultdict, OrderedDict
from functools import partial
from lxml import etree
from multiprocessing import Event, Process, Queue
from queue import Empty
import argparse
import os
import re
import signal

PORT_SERVICES = [
    {
        'tag': 'ReportItem',
        'filters': [
            {'pluginFamily': ['Service detection', 'Port scanners']},
            {'pluginName': ['Netstat Active Connections', 'Local Checks Not Enabled (info)']}
        ],
        'extract': 'plugin_output'
    },
    {
        'tag': 'tag',
        'filters': [
            {'name': 'Credentialed_Scan'}
        ]
    }
]

SMB_SIGNING = [
    {
        'tag': 'ReportItem',
        'filters': [
            {'pluginName': ['SMB Signing not required']}
        ]
    }
]

SELINUX = [
    {
        'tag': 'ReportItem',
        'filters': [
            {'pluginName': ['SELinux Status Check']}
        ],
        'extract': 'plugin_output'
    }
]

AGENT = [
    {
        'tag': 'ReportItem',
        'filters': [
            {'pluginName': ['Microsoft Windows SMB Service Config Enumeration', 'Unix / Linux Running Processes Information']}
        ],
        'extract': 'plugin_output'
    }
]

ALL = [
    {'tag': 'ReportItem', 'extract': 'plugin_output'}
]

SEARCHES = PORT_SERVICES
LXML_OPTIONS = {
    'encoding': 'unicode',
    'pretty_print': True
}

def open_files(nessus_files):
    for file in nessus_files:
        with open(file, 'r', encoding='utf-8') as f:
            file_contents = f.read()
        yield file, file_contents

def list_port(values):
    try:
        ports = [int(value.strip()) for value in values.split(',')]
    except ValueError:
        with open(values, 'r') as f:
            ports = f.readlines()
        ports = [int(port.strip()) for port in ports if port.strip()]
    dedup_ports = []
    for port in ports:
        if port not in dedup_ports:
            dedup_ports.append(port)
    return dedup_ports

def list_ips(values):
    IP_REGEX = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ips = IP_REGEX.findall(values)
    if not ips:
        with open(values, 'r') as f:
            ips = f.readlines()
            ips = [ip.strip() for ip in ips if IP_REGEX.fullmatch(ip.strip())]
    dedup_ips = []
    for ip in ips:
        if ip not in dedup_ips:
            dedup_ips.append(ip)
    return dedup_ips

def extract_general(item, extract, general_findings):
    if extract:
        output = item.find(f'.//{extract}')
        if output is not None:
            general_findings.add( etree.tostring(output, **LXML_OPTIONS) )
    else:
        general_findings.add( etree.tostring(item, **LXML_OPTIONS) )
    return general_findings

def extract_proto_port(item, extract, port, proto_port_findings):
    proto = item.get('protocol')
    if extract:
        output = item.find(f'.//{extract}')
        if output is not None:
            output.attrib['pluginName'] = item.get('pluginName')
            proto_port_findings[proto][int(port)].add( etree.tostring(output, **LXML_OPTIONS) )
    else:
        proto_port_findings[proto][int(port)].add( etree.tostring(item, **LXML_OPTIONS) )
    return proto_port_findings

def run_search(result, tag, filters, extract, general_findings, proto_port_findings):
    if not filters:
        found = result.findall(f'.//{tag}')
        for item in found:
            port = item.get('port')
            if not port:
                general_findings = extract_general(item, extract, general_findings)
                continue
            proto_port_findings = extract_proto_port(item, extract, port, proto_port_findings)
    else:
        for filter_ in filters:
            for attr, values in filter_.items():
                if isinstance(values, list):
                    for value in values:
                        found = result.findall(f'.//{tag}[@{attr}="{value}"]')
                        for item in found:
                            port = item.get('port')
                            if not port:
                                general_findings = extract_general(item, extract, general_findings)
                                continue
                            proto_port_findings = extract_proto_port(item, extract, port, proto_port_findings)
                else:
                    found = result.findall(f'.//{tag}[@{attr}="{values}"]')
                    for item in found:
                        port = item.get('port')
                        if not port:
                            general_findings = extract_general(item, extract, general_findings)
                            continue
                        proto_port_findings = extract_proto_port(item, extract, port, proto_port_findings)
    return general_findings, proto_port_findings

def get_all_findings(results, general_findings=None, proto_port_findings=None):
    if not general_findings:
        general_findings = set()
    if not proto_port_findings:
        proto_port_findings = defaultdict(lambda: defaultdict(set))

    for result in results:
        for search in SEARCHES:
            tag = search.get('tag')
            filters = search.get('filters')
            extract = search.get('extract')
            general_findings, proto_port_findings = run_search(
                result, tag, filters, extract,
                general_findings, proto_port_findings
            )
    return general_findings, proto_port_findings

def write_general_findings_loop(output, general_findings):
    if isinstance(general_findings, OrderedDict):
        filename_general_findings = general_findings
        for filename, general_findings in filename_general_findings.items():
            output.write(f'========== {filename} ==========\n')
            for finding in sorted(general_findings):
                output.write(finding.strip() + '\n')
            if general_findings:
                output.write('\n\n')
    else:
        for finding in sorted(general_findings):
            output.write(finding.strip() + '\n')
    if not general_findings:
        output.write('\n\n')

def write_proto_port_findings_loop(output, proto_port_findings):
    if isinstance(proto_port_findings, OrderedDict):
        filename_proto_port_findings = proto_port_findings
        for filename, proto_port_findings in filename_proto_port_findings.items():
            output.write(f'========== {filename} ==========\n')
            for proto in sorted(proto_port_findings.keys()):
                port_mapped_findings = proto_port_findings.get(proto)
                for port in sorted(port_mapped_findings.keys()):
                    fill = ( len(proto) + len(str(port)) ) * '~'
                    output.write(f'/~~~~~~~~~~~{fill}/\n')
                    output.write(f'/~~~ {proto} - {port} ~~~/\n')
                    output.write(f'/~~~~~~~~~~~{fill}/\n')
                    results = port_mapped_findings.get(port)
                    for result in sorted(results):
                        output.write(result.strip() + '\n')
                    output.write('\n\n')
    else:
        for proto in sorted(proto_port_findings.keys()):
            port_mapped_findings = proto_port_findings.get(proto)
            for port in sorted(port_mapped_findings.keys()):
                fill = ( len(proto) + len(str(port)) ) * '~'
                output.write(f'/~~~~~~~~~~~{fill}/\n')
                output.write(f'/~~~ {proto} - {port} ~~~/\n')
                output.write(f'/~~~~~~~~~~~{fill}/\n')
                results = port_mapped_findings.get(port)
                for result in sorted(results):
                    output.write(result.strip() + '\n')
                output.write('\n\n')

def write_to_file(output, general_findings, proto_port_findings):
    output.write('/**************************************/\n')
    output.write('/********** General Findings **********/\n')
    output.write('/**************************************/\n')
    write_general_findings_loop(output, general_findings)
    
    output.write('/***********************************/\n')
    output.write('/********** Port Findings **********/\n')
    output.write('/***********************************/\n')
    write_proto_port_findings_loop(output, proto_port_findings)

def unmerge_mode(args, nessus_files, ip):
    output_filename = os.path.join(args.output, f'{args.file}-{ip}.xml')

    filename_general_findings = OrderedDict()
    filename_proto_port_findings = OrderedDict()
    for filename, file_contents in open_files(nessus_files):
        tree = etree.fromstring(file_contents)
        results = tree.findall(f'.//ReportHost[@name=\"{ip}\"]')
        general_findings, proto_port_findings = get_all_findings(results)
        if results:
            filename_general_findings[filename] = general_findings
            filename_proto_port_findings[filename] = proto_port_findings

    with open(output_filename, 'w', encoding='utf-8') as output:
        write_to_file(output, filename_general_findings, filename_proto_port_findings)

def default_mode(args, nessus_files, ip):
    output_filename = os.path.join(args.output, f'{args.file}-{ip}.xml')

    general_findings = set()
    proto_port_findings = defaultdict(lambda: defaultdict(set))
    for _, file_contents in open_files(nessus_files):
        tree = etree.fromstring(file_contents)
        results = tree.findall(f'.//ReportHost[@name=\"{ip}\"]')
        general_findings, proto_port_findings = get_all_findings(results, general_findings, proto_port_findings)
    
    with open(output_filename, 'w', encoding='utf-8') as output:
        write_to_file(output, general_findings, proto_port_findings)

def worker(start, job_queue, target, args, nessus_files):
    def worker_term(sig_num, frame):
        import sys
        sys.exit(0)

    signal.signal(signal.SIGINT, worker_term)
    start.wait()
    while not job_queue.empty():
        try:
            ip = job_queue.get_nowait()
            print(f'Starting collation for {ip}')
            target(args, nessus_files, ip)
            print(f'Collation for {ip} completed!')
        except Empty:
            pass

def search_directories():
    if args.recursive:
        nessus_files = []
        for root, _, files in os.walk(args.directory):
            for name in files:
                if os.path.splitext(name)[1] == '.nessus':
                    nessus_files.append(os.path.join(root, name))
    else:
        nessus_files = [f for f in os.listdir(args.directory) if os.path.splitext(f)[1] == '.nessus']
        nessus_files = [os.path.join(args.directory, f) for f in nessus_files]
        nessus_files = [f for f in nessus_files if os.path.isfile(f)]
    return nessus_files

def main():
    nessus_files = search_directories()
    os.makedirs(args.output, exist_ok=True)
    if args.unmerge:
        target = unmerge_mode
    else:
        target = default_mode
    
    start = Event()
    job_queue = Queue()
    for ip in args.ip_addr:
        job_queue.put(ip)
    
    procs = []
    for _ in range(args.processes):
        proc = Process(target=worker, args=(start, job_queue, target, args, nessus_files))
        proc.start()
        procs.append(proc)

    try:
        start.set()
        for proc in procs:
            proc.join()
    except KeyboardInterrupt:
        print('Interrupted...')
        for proc in procs:
            proc.terminate()
            proc.join()
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run through nessus files to get port', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument(
        '-ip', '--ip-address', type=list_ips,
        dest='ip_addr', required=True, help='IP address to search for')
    parser.add_argument(
        '-r', '--recursive', action='store_true',
        help='Search through directory recursively')
    parser.add_argument(
        '-u', '--unmerge', action='store_true',
        help='Do not merge findings and separate them by the files in which they were found in')
    parser.add_argument(
        '-d', '--directory',
        default='.', help=f'Directory containing exported nessus scan files{os.linesep}(Default: ".")')
    parser.add_argument(
        '-o', '--output-directory', dest='output', default='processed',
        help=f'Directory to output files to{os.linesep}(Default: "processed")')
    parser.add_argument(
        '-f', '--file-prefix', dest='file', metavar='PREFIX', default='processed',
        help=f'Prefix to prepend to output files{os.linesep}(Default: "processed")')
    parser.add_argument(
        '-p', '--ports', type=list_port, default=[i for i in range(65536)],
        help=f'Port to search for{os.linesep}'
            'Accepts file with a list of ports or access a string containing comma-separated port values (Default: All ports)')
    parser.add_argument(
        '-n', '--num-processes', type=int, default=5,
        dest='processes', help='Specifies number of processes to spawn')
    args = parser.parse_args()
    main()
