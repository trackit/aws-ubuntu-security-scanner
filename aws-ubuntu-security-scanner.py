import platform
import paramiko
import base64
import csv
import json
import ConfigParser
import argparse
import sys
from datetime import datetime

class Parser(argparse.ArgumentParser):
    def print_help(self, file=sys.stdout):
        super(Parser, self).print_help(file)
    def error(self, message):
        print(message)
        self.print_help()
        sys.exit(2)


def parse_args():
    parser = Parser()
    now = datetime.now()
    parser.add_argument(
        "--key",
        help="Path to private ssh key",
        dest="key",
        default="~/.ssh/id_rsa",
    )
    parser.add_argument(
        "--hosts",
        help="Path to host list",
        dest="host",
        default="hosts",
    )
    parser.add_argument(
        "--username",
        help="Ssh username",
        dest="username",
        default="bastien",
    )
    now = datetime.now()
    parser.add_argument(
        "--csv-prefix",
        help="Specify prefixe name for csv output",
        dest="csv",
        default=now.strftime("monitoring_report_%Y_%m_%d"),
    )
    parser.add_argument(
        "--passphrase",
        help="Passphrase for private key (optional)",
        dest="passphrase",
        default=""
    )
    return parser.parse_args(), parser

def get_hosts_list(filename):
    tab = []
    f = open(filename)
    for l in f.readlines():
        tab.append(l.strip('\n'))
    return tab

def generate_csv(filename, data, header_name):
    # filename = "report.csv"
    with open(filename, 'wb') as file:
        writer = csv.DictWriter(file, header_name)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

def pacakge_get_name(package):
    p = package.split('/')
    return p[0]

def package_get_version(package):
    p = package.split('/')
    v = p[1].split(',')
    if "[" in v[0]:
        return v[0].split('[')[0]
    if len(v) <= 1:
        return v[0]
    if "[" in v[1]:
        return v[1].split('[')[0]
    return v[1]    

def package_get_upgradable(pacakge):
    p = pacakge.replace("]","").split('/')
    v = p[1].split('[')
    u = v[1].split(',')
    if len(u) <= 1:
        return "uptodate"
    return u[1].replace("upgradable to: ", "")

def parse_package(package):
    name = pacakge_get_name(package)
    version = package_get_version(package)
    upg = package_get_upgradable(package)
    return name, version, upg

def main():
    args, parser = parse_args()
    kernel_csv = []
    pkg_csv = []
    keys_csv = []
    hosts = get_hosts_list(args.host)
    print hosts
    key = paramiko.RSAKey.from_private_key_file(args.key, password=args.passphrase)
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for host in hosts:
        client.connect(host, port=22, username=args.username, pkey=key)
        stdin, stdout, stderr = client.exec_command('uname -a')
        kernel = ''
        for line in stdout:
            kernel += line.strip('\n')
        kernel_csv += [
            {
                'host': host,
                'kernel': kernel
            }
        ]
        stdin, stdout, stderr = client.exec_command('apt list --installed')
        for line in stdout:
            if line != "Listing...\n":
                n, p, u = parse_package(line.strip('\n'))
                if u != "uptodate" and u != "automatic" and u != "local":
                    pkg_csv += [
                        {
                            'host': host,
                            'package': n,
                            'current_version': p,
                            "upgradable": u
                        }
                    ]
        stdin, stdout, stderr = client.exec_command('ls -1 /home')
        for user in stdout:
            user = user.replace("\n", "")
            cmd = "sudo cat /home/" + user + "/.ssh/authorized_keys"
            stdin, a_keys, stderr = client.exec_command(cmd)
            for key in a_keys:
                keys_csv += [
                    {
                        'host': host,
                        'user': user,
                        'key': key
                    }
                ]

    generate_csv(args.csv+'_kernel.csv', kernel_csv, ['host', 'kernel'])
    generate_csv(args.csv+'_apt.csv', pkg_csv, ['host', 'package', 'current_version', 'upgradable'])
    generate_csv(args.csv+'_keys.csv', keys_csv, ['host', 'user', 'key'])
    client.close()

if __name__ == "__main__":
    main()