import boto3
import botocore
import csv
import pprint
import argparse
import ConfigParser
import os

"""
A tool for retrieving basic information from the running EC2 instances.
"""

def get_regions(session):
    client = session.client('ec2')
    regions = client.describe_regions()
    return [
        region['RegionName']
        for region in regions['Regions']
    ]


def get_ec2_resources(session, regions, account):
    res = []
    for region in regions:
        ec2 = session.resource('ec2', region_name=region)
        running_instances = ec2.instances.filter(Filters=[{
            'Name': 'instance-state-name',
            'Values': ['running']}])
        for instance in running_instances:
            for tag in instance.tags:
                if 'Name'in tag['Key']:
                    name = tag['Value']
            res += [
                {
                    'Instance ID': instance.id,
                    'Account': account,
                    'Region': region,
                    'Name': name,
                    'Private IP': instance.private_ip_address
                }
            ]
    return res

def generate_csv(data, args, header_name):
    filename = "report.csv"
    if args['o']:
        filename = args['o']
    with open(filename, 'wb') as file:
        writer = csv.DictWriter(file, header_name)
        writer.writeheader()
        for row in data:
            writer.writerow(row)

def init():
    config_path = os.environ.get('HOME') + "/.aws/credentials"
    parser = ConfigParser.ConfigParser()
    parser.read(config_path)
    if parser.sections():
        return parser.sections()
    return []

def main():
    data = []
    parser = argparse.ArgumentParser(description="Analyse reserved instances")
    parser.add_argument("--profile", nargs="+", help="Specify AWS profile(s) (stored in ~/.aws/credentials) for the program to use")
    parser.add_argument("-o", nargs="?", help="Specify output csv file")
    parser.add_argument("--profiles-all", nargs="?", help="Run it on all profile")
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_region = os.environ.get('AWS_DEFAULT_REGION')
    args = vars(parser.parse_args())
    if 'profiles-all' in args:
        keys = init()
    elif 'profile' in args and args['profile']:
        keys = args['profile']
    else:
        keys = init()
    for key in keys:
        print 'Processing %s...' % key
        try:
            if aws_access_key and aws_secret_key and aws_region:
                session = boto3.Session(aws_access_key_id=aws_access_key, aws_secret_access_key=aws_secret_key, region_name=aws_region)
            else:
                session = boto3.Session(profile_name=key)
            regions = get_regions(session)
            data += get_ec2_resources(session, regions, key)
        except botocore.exceptions.ClientError, error:
            print error
    generate_csv(data, args, ['Account', 'Region', 'Name', 'Private IP', 'Instance ID'])


if __name__ == '__main__':
    main()
