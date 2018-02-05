'''
DNS site lookup
'''
import logging
from random import randint

import geoip2.database
import ipaddr

import yaml
try:
    from yaml import CLoader as Loader # load C parser
except ImportError:
    from yaml import Loader            # fallback to pure Python

# From https://github.com/phihag/ipaddress/blob/master/ipaddress.py
# because we cannot have python-ipaddress.
_IPV4_PRIVATE_NETWORKS = [
    ipaddr.IPv4Network(net)
    for net in [
            '0.0.0.0/8',
            '10.0.0.0/8',
            '127.0.0.0/8',
            '169.254.0.0/16',
            '172.16.0.0/12',
            '192.0.0.0/29',
            '192.0.0.170/31',
            '192.0.2.0/24',
            '192.168.0.0/16',
            '198.18.0.0/15',
            '198.51.100.0/24',
            '203.0.113.0/24',
            '240.0.0.0/4',
            '255.255.255.255/32',
    ]
]

_IPV6_PRIVATE_NETWORKS = [
    ipaddr.IPv6Network(net)
    for net in [
            '::1/128',
            '::/128',
            '::ffff:0:0/96',
            '100::/64',
            '2001::/23',
            '2001:2::/48',
            '2001:db8::/32',
            '2001:10::/28',
            'fc00::/7',
            'fe80::/10',
    ]
]

def reserved(address):
    '''Test for valid IPv4 or IPv6 address and checks whether it is reserved.'''
    try:
        ip = ipaddr.IPAddress(unicode(address))
        return (
            ip.is_private or
            ip.is_multicast or
            ip.is_unspecified or
            ip.is_loopback or
            ip.is_link_local or (
                isinstance(ip, ipaddr.IPv4Address) and (
                    any(ip in net for net in _IPV4_PRIVATE_NETWORKS) or
                    ip in ipaddr.IPv4Network('100.64.0.0/10')
                )
            ) or (
                isinstance(ip, ipaddr.IPv6Address) and
                any(ip in net for net in _IPV6_PRIVATE_NETWORKS)
            )
        )
    except ValueError:
        return True

    return False

def zone(georeader, zones, remoteip, edns='0.0.0.0/8'):
    '''Zone lookup using GeoIP2 City database

    The zones variable must be a dict abiding to the following rule:
      1. a key may be 'default' or an ISO 3166-1 alpha-2 country code
      2. there has to be one and only one key named 'default'
      3. the 'default' key must have a string value
      4. a key may have a string (zone to return) or a dict value
      5. in case of dict value:
        1. a key may be 'default' or the second part of an ISO 3166-2 code
        2. there has to be one and only one key named 'default'
        3. the 'default' key must have a string value

    Example (YAML syntax):
      'default': eu
      'FR':      eu
      'US':
        'default': us-east
        'CA':      us-west
    '''

    # Default zone to return is under 'default'
    default_zone = zones['default']

    # Get rid of netmask in edns
    edns = edns.split('/')[0]

    # If EDNS is reserved, pick the remote ip
    if reserved(edns):
        # If remote ip is reserved, return default zone
        if reserved(remoteip):
            logging.info('Reserved address: %s!', remoteip)
            return default_zone
        else:
            address = remoteip
    else:
        address = edns

    # Geolocate the address using GeoIPv2 City
    try:
        geo = georeader.city(address)
    except geoip2.errors.AddressNotFoundError:
        logging.warning('Address not found in GeoIP database: %s!', address)
        return default_zone

    # Get zone for given country code
    country = geo.country.iso_code
    gzone = zones.get(country, default_zone)

    # If the returned zone is a dict
    # return zone for given region code
    if isinstance(gzone, dict):
        # Get zone for given region code
        region = geo.subdivisions.most_specific.iso_code
        default_zone = zones[country]['default']

        return gzone.get(region, default_zone)
    else:
        return gzone

def site(sites, qname, qzone, qclass='IN', qtype='ANY'):
    '''Site lookup returns [(type, ip, ttl), ...]

    The sites variable must be a dict abiding to the following format:
    <fqdn>:
      <class>:
        <type>:
          content:
            <zone>:
              <ip>: <weight>

    <fqdn>   - may be a FQDN or a DNS wildcard
    <class>  - a DNS class
    <type>   - a DNS type
    <zone>   - a string, there has to be one 'default' key
    <ip>     - an IP
    <weight> - a number representing the weight for weighted round robin

    Example (in YAML format):
      www.example.com:
        IN:
          A:
            content:
              default:
                1.1.1.1: 20
                2.2.2.2: 80
              us:
                3.3.3.3: 100
      '*.example.com':
        IN:
          A:
            content:
              default:
                1.1.1.1: 100
    '''

    # Literal site check
    if qname not in sites:
        # Wildcard site check
        wildcard = '*' + qname[qname.find('.'):]
        if wildcard in sites:
            qname = wildcard
        else:
            logging.warning('No such site: %s!', qname)
            return []

    try:
        mclass = sites[qname][qclass]
    except KeyError:
        logging.warning('No match for: %s %s!', qname, qclass)
        return []

    if qtype == 'ANY':
        qtypes = sorted(mclass.keys())
    elif qtype in mclass:
        qtypes = [qtype]
    else:
        logging.warning('No match for: %s %s %s!', qname, qclass, qtype)
        return []

    sites = []
    for qtype in qtypes:
        mname = mclass[qtype]
        mttl = mname.get('ttl', 3600)
        mcontent = mname['content'].get(qzone, mname['content']['default'])

        # Weighted round robin algorithm
        address = mcontent.keys()[0]
        if len(mcontent) > 1:
            # Create a random integer between 1 the total sum
            rnd = randint(1, sum(mcontent.values()))
            # Get weighted random address
            upto = 0
            for address in sorted(mcontent):
                if rnd <= upto + mcontent[address]:
                    break
                upto += mcontent[address]

        sites.append((qtype, address, mttl))

    return sites

def geoip(filename):
    '''Load MaxMindDB'''
    reader = geoip2.database.Reader(filename)
    return reader

def conf(filename):
    '''Load configuration from YAML'''
    with open(filename, 'r') as stream:
        parsed = yaml.load(stream, Loader)
    return parsed
