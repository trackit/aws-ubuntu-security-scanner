import platform
import paramiko
import base64
import csv
import json
import ConfigParser
import argparse
import sys
from datetime import datetime
import xlsxwriter
import boto3
import socket
import os

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
        "--port",
        help="SSH port",
        dest="port",
        default="22",
    )
    parser.add_argument(
        "--password",
        help="Path to private ssh key",
        dest="password",
        default="passwd",
    )
    parser.add_argument(
        "--s3",
        help="Bucket name",
        dest="s3",
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
        "--output",
        help="Specify filename for output",
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

def check_if_security_update(p, s):
    if p in s:
        return "*"
    return ""

def main():
    args, parser = parse_args()
    kernel_csv = []
    pkg_csv = []
    keys_csv = []
    cve_csv = []
    hosts = get_hosts_list(args.host)
    print hosts
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for host in hosts:
        print "Connecting to "+host
        try:
            key = paramiko.RSAKey.from_private_key_file(args.key, password=args.passphrase)
            client.connect(host, port=args.port, username=args.username, pkey=key)
            hostname = ''
            stdin, stdout, stderr = client.exec_command('hostname -f')
            for line in stdout:
                hostname += line.strip('\n')
            stdin, stdout, stderr = client.exec_command('uname -a')
            kernel = ''
            for line in stdout:
                kernel += line.strip('\n')
            stdin, stdout, stderr = client.exec_command('lsb_release -cs')
            for l in stdout:
                codename = l.replace("\n", "")
            kernel_csv += [
                {
                    'host': host,
                    'hostname': hostname,
                    'ubuntu_version': codename,
                    'kernel': kernel
                }
            ]
            cmd = "echo " + args.password + " | sudo -S unattended-upgrade --dry-run -d 2> /dev/null | awk '/Checking/ { print $2 }'"
            stdin, stdout, stderr = client.exec_command(cmd)
            security_pkg = []
            for p in stdout:
                security_pkg.append(p.replace("\n", ""))
            stdin, stdout, stderr = client.exec_command('apt list --installed')
            f = open('tmp_pkg.txt', 'a')
            for line in stdout:
                if line != "Listing...\n":
                    f.write(line)
                    n, p, u = parse_package(line.strip('\n'))
                    s = check_if_security_update(n, security_pkg)
                    if u != "uptodate" and u != "automatic" and u != "local" and u != "auto-removable":
                        pkg_csv += [
                            {
                                'host': host,
                                'hostname': hostname,
                                'ubuntu_version': codename,
                                'package': n,
                                'current_version': p,
                                "upgradable": u,
                                "security": s
                            }
                        ]
            stdin, stdout, stderr = client.exec_command('ls -1 /home')
            for user in stdout:
                user = user.replace("\n", "")
                cmd = "echo " + args.password + " | sudo -S cat /home/" + user + "/.ssh/authorized_keys{,1,2,3}"
                stdin, a_keys, stderr = client.exec_command(cmd,get_pty=True)
                for key in a_keys:
                    if "Password:" not in key and "ssh-rsa" in key:
                        keys_csv += [
                            {
                                'host': host,
                                'hostname': hostname,
                                'user': user,
                                'key': key
                            }
                        ]

            # stdin, stdout, stderr = client.exec_command('lsb_release -cs')
            # for l in stdout:
            #     codename = l.replace("\n", "")
            # os.system("python active-cve-check/scan_packages.py tmp_pkg.txt ubuntu-cve-tracker/active --ubuntu-version=" + codename + " > rezpkg")
            # with open('rezpkg') as f:
            #     lines = f.readlines()
            # for l in lines:
            #     pkg = l.split(';')
            #     if len(pkg) > 2:
            #         published = pkg[2]
            #         modified = pkg[3]
            #         summary = pkg[4]
            #     else:
            #         published = "NA"
            #         modified = "NA"
            #         summary = "NA" 
            #     cve_csv += [
            #         {
            #             'host': host,
            #             'hostname': hostname,
            #             'cve': pkg[0],
            #             'package': pkg[1],
            #             'published': published,
            #             'modified': modified,
            #             'summary': summary

            #         }
            #     ]                
            # # os.remove('tmp_pkg.txt')
            # os.remove('rezpkg')



        # except socket.timeout:    
        #     print ("Unable to connect to " + host)
        #     pass
        #     continue

        # except socket.error : 
        #     print ("Unable to connect to " + host)
        #     pass
        #     continue

        # except paramiko.SSHException, socket.error :
        #     print ("Unable to connect to " + host)
        #     pass
        #     continue
        except:
            print ("Unable to connect to " + host)
            pass
            continue       

    csv_list = []
    csv_list.append('kernel_'+args.csv)
    csv_list.append('apt_'+args.csv)
    csv_list.append('keys_'+args.csv)
    # csv_list.append('cve_'+args.csv)


    generate_csv(csv_list[0], kernel_csv, ['host','hostname', 'ubuntu_version', 'kernel'])
    generate_csv(csv_list[1], pkg_csv, ['host', 'hostname', 'ubuntu_version', 'package', 'current_version', 'upgradable', 'security'])
    generate_csv(csv_list[2], keys_csv, ['host', 'hostname', 'user', 'key'])
    # generate_csv(csv_list[3], cve_csv, ['host', 'hostname', 'cve', 'package', 'published', 'modified', 'summary'])

    workbook = xlsxwriter.Workbook(args.csv)
    for csvfile in csv_list:
        worksheet = workbook.add_worksheet(csvfile.split('_')[0])
        with open(csvfile, 'rt') as f:
            reader = csv.reader(f)
            for r, row in enumerate(reader):
                for c, col in enumerate(row):
                    worksheet.write(r, c, col)
        os.remove(csvfile)
    workbook.close()

    if args.s3:
        s3 = boto3.resource('s3')
        data = open(args.csv, 'rb')
        now = datetime.now()
        filename = now.strftime("monitoring_report_%Y_%m_%d")
        s3.Bucket(args.s3).put_object(Key=filename, Body=data)

    client.close()

if __name__ == "__main__":
    main()
