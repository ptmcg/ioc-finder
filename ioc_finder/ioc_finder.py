#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Python package for finding indicators of compromise in text."""

import asyncio
import json
import os
import sys

import click
import ioc_fanger

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))
import ioc_grammars


def _deduplicate(indicator_list):
    """Deduplicate the list of indicators of compromise."""
    return list(set(indicator_list))


def _listify(indicator_list):
    """Convert the multi-dimensional indicator list into a one-dimensional indicator list with empty entries and duplicates removed."""
    return _deduplicate([indicator[0] for indicator in indicator_list if indicator[0]])


def _remove_items(items, text):
    """Remove each item from the text."""
    for item in items:
        text = text.replace(item, ' ')
    return text


def prepare_text(text):
    """Fang (https://ioc-fang.hightower.space/) and encode the text in such a way that all Unicode domain names are converted into their punycode representation."""
    text = ioc_fanger.fang(text)
    # text = text.encode('idna').decode('utf-8')
    return text


def parse_urls(text, parse_urls_without_scheme=True):
    """."""
    if parse_urls_without_scheme:
        urls = ioc_grammars.scheme_less_url.searchString(text)
    else:
        urls = ioc_grammars.url.searchString(text)
    urls = _listify(urls)

    clean_urls = []

    # clean the url
    for url in urls:
        # remove `"` and `'` characters from the end of a URL
        url = url.rstrip('"').rstrip("'")

        # remove a final ')' if there is a '(' in the url
        if url.endswith(')') and '(' not in url:
            url = url.rstrip(')')

        clean_urls.append(url)

    # return the cleaned urls - I deduplicate them again because the structure of the URL may have changed when it was cleaned
    return _deduplicate(clean_urls)


def _remove_url_paths(urls, text, parse_urls_without_scheme=True):
    """Remove the path from each url from the text."""
    for url in urls:
        if parse_urls_without_scheme:
            parsed_url = ioc_grammars.scheme_less_url.parseString(url)
        else:
            parsed_url = ioc_grammars.url.parseString(url)
        url_path = parsed_url.url_path

        # handle situations where the parsed url is likely a cidr range
        if parse_urls_without_scheme and parse_ipv4_cidrs(str(url)):
            pass
        elif len(url_path) > 1:
            text = text.replace(url_path, ' ')
    return text


async def parse_domain_names(text):
    """."""
    await asyncio.sleep(0)
    domains = ioc_grammars.domain_name.searchString(text.lower())
    return _listify(domains)


async def parse_ipv4_addresses(text):
    """."""
    await asyncio.sleep(0)
    addresses = ioc_grammars.ipv4_address.searchString(text)
    return _listify(addresses)


async def parse_ipv6_addresses(text):
    """."""
    await asyncio.sleep(0)
    addresses = ioc_grammars.ipv6_address.searchString(text)
    return _listify(addresses)


def parse_complete_email_addresses(text):
    """."""
    email_addresses = ioc_grammars.complete_email_address.searchString(text)
    return _listify(email_addresses)


def parse_email_addresses(text):
    """."""
    email_addresses = ioc_grammars.email_address.searchString(text)
    return _listify(email_addresses)


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_imphashes_(text):
    """."""
    full_imphash_instances = ioc_grammars.imphash.searchString(text.lower())
    full_imphash_instances = _listify(full_imphash_instances)

    imphashes = []

    for imphash in full_imphash_instances:
        imphashes.append(ioc_grammars.imphash.parseString(imphash).hash[0])

    return imphashes


# there is a trailing underscore on this function to differentiate it from the argument with the same name
def parse_authentihashes_(text):
    """."""
    full_authentihash_instances = ioc_grammars.authentihash.searchString(text.lower())
    full_authentihash_instances = _listify(full_authentihash_instances)

    authentihashes = []

    for authentihash in full_authentihash_instances:
        authentihashes.append(ioc_grammars.authentihash.parseString(authentihash).hash[0])

    return authentihashes


async def parse_md5s(text):
    """."""
    await asyncio.sleep(0)
    md5s = ioc_grammars.md5.searchString(text)
    return _listify(md5s)


async def parse_sha1s(text):
    """."""
    await asyncio.sleep(0)
    sha1s = ioc_grammars.sha1.searchString(text)
    return _listify(sha1s)


async def parse_sha256s(text):
    """."""
    await asyncio.sleep(0)
    sha256s = ioc_grammars.sha256.searchString(text)
    return _listify(sha256s)


async def parse_sha512s(text):
    """."""
    await asyncio.sleep(0)
    sha512s = ioc_grammars.sha512.searchString(text)
    return _listify(sha512s)


async def parse_ssdeeps(text):
    """."""
    await asyncio.sleep(0)
    ssdeeps = ioc_grammars.ssdeep.searchString(text)
    return _listify(ssdeeps)


async def parse_asns(text):
    """."""
    await asyncio.sleep(0)
    asns = ioc_grammars.asn.searchString(text)
    return _listify(asns)


async def parse_cves(text):
    """."""
    await asyncio.sleep(0)
    cves = ioc_grammars.cve.searchString(text)
    return _listify(cves)


def parse_ipv4_cidrs(text):
    """."""
    cidrs = ioc_grammars.ipv4_cidr.searchString(text)
    return _listify(cidrs)


# def parse_ipv6_cidrs(text):
#     """."""
#     # TODO: implement
#     cidrs = ioc_grammars.ipv6_cidr.searchString(text)
#     return _listify(cidrs)


async def parse_registry_key_paths(text):
    """."""
    await asyncio.sleep(0)
    parsed_registry_key_paths = ioc_grammars.registry_key_path.searchString(text)
    full_parsed_registry_key_paths = _listify(parsed_registry_key_paths)

    registry_key_paths = []
    for registry_key_path in full_parsed_registry_key_paths:
        # if there is a space in the last section of the parsed registry key path, remove it so that content after a registry key path is not also pulled in... this is a limitation of the grammar: it will not parse a registry key path with a space in the final section (the section after the final '\')
        if ' ' in registry_key_path.split('\\')[-1]:
            registry_key_paths.append(' '.join(registry_key_path.split(' ')[:-1]))
        else:
            registry_key_paths.append(registry_key_path)

    return registry_key_paths


async def parse_google_adsense_ids(text):
    """."""
    await asyncio.sleep(0)
    adsense_publisher_ids = ioc_grammars.google_adsense_publisher_id.searchString(text)
    return _listify(adsense_publisher_ids)


async def parse_google_analytics_ids(text):
    """."""
    await asyncio.sleep(0)
    analytics_tracker_ids = ioc_grammars.google_analytics_tracker_id.searchString(text)
    return _listify(analytics_tracker_ids)


async def parse_bitcoin_addresses(text):
    """."""
    await asyncio.sleep(0)
    bitcoin_addresses = ioc_grammars.bitcoin_address.searchString(text)
    return _listify(bitcoin_addresses)


def parse_xmpp_addresses(text):
    """."""
    xmpp_addresses = ioc_grammars.xmpp_address.searchString(text)
    return _listify(xmpp_addresses)


def _remove_xmpp_local_part(xmpp_addresses, text):
    """Remove the local part of each xmpp_address from the text."""
    for address in xmpp_addresses:
        text = text.replace(address.split('@')[0] + '@', ' ')

    return text


async def parse_mac_addresses(text):
    """."""
    await asyncio.sleep(0)
    mac_addresses = ioc_grammars.mac_address.searchString(text)
    return _listify(mac_addresses)


async def parse_user_agents(text):
    """."""
    await asyncio.sleep(0)
    user_agents = ioc_grammars.user_agent.searchString(text)
    return _listify(user_agents)


async def parse_file_paths(text):
    """."""
    await asyncio.sleep(0)
    file_paths = ioc_grammars.file_path.searchString(text)
    return _listify(file_paths)


async def parse_phone_numbers(text):
    """."""
    await asyncio.sleep(0)
    phone_numbers = ioc_grammars.phone_number.searchString(text[::-1])
    return [phone_number[::-1] for phone_number in _listify(phone_numbers)]


@click.command()
@click.argument('text')
@click.option('--no_url_domain_parsing', is_flag=True, help='Using this flag will not parse domain names from URLs')
@click.option(
    '--no_email_addr_domain_parsing',
    is_flag=True,
    help='Using this flag will not parse domain names from email addresses',
)
@click.option(
    '--no_cidr_address_parsing', is_flag=True, help='Using this flag will not parse IP addresses from CIDR ranges'
)
@click.option(
    '--no_xmpp_addr_domain_parsing',
    is_flag=True,
    help='Using this flag will not parse domain names from XMPP addresses',
)
@click.option('--no_urls_without_schemes', is_flag=True, help='Using this flag will not parse URLs without schemes')
@click.option('--no_import_hashes', is_flag=True, help='Using this flag will not parse import hashes')
@click.option('--no_authentihashes', is_flag=True, help='Using this flag will not parse authentihash')
def cli_find_iocs(
    text,
    no_url_domain_parsing,
    no_email_addr_domain_parsing,
    no_cidr_address_parsing,
    no_xmpp_addr_domain_parsing,
    no_urls_without_schemes,
    no_import_hashes,
    no_authentihashes,
):
    """CLI interface for parsing indicators of compromise."""
    iocs = find_iocs(
        text,
        not no_url_domain_parsing,
        not no_email_addr_domain_parsing,
        not no_cidr_address_parsing,
        not no_xmpp_addr_domain_parsing,
        not no_urls_without_schemes,
        not no_import_hashes,
        not no_authentihashes,
    )
    ioc_string = json.dumps(iocs, indent=4, sort_keys=True)
    print(ioc_string)


def find_iocs(
    text,
    parse_domain_from_url=True,
    parse_domain_from_email_address=True,
    parse_address_from_cidr=True,
    parse_domain_name_from_xmpp_address=True,
    parse_urls_without_scheme=True,
    parse_imphashes=True,
    parse_authentihashes=True,
):
    """Find indicators of compromise in the given text."""
    iocs = dict()

    text = prepare_text(text)

    # urls
    iocs['urls'] = parse_urls(text, parse_urls_without_scheme)
    if not parse_domain_from_url:
        text = _remove_items(iocs['urls'], text)
    # even if we want to parse domain names from the urls, we need to remove the urls's paths to make sure no domain names are incorrectly parsed from the urls's paths
    else:
        text = _remove_url_paths(iocs['urls'], text, parse_urls_without_scheme)

    # xmpp addresses
    iocs['xmpp_addresses'] = parse_xmpp_addresses(text)
    if not parse_domain_name_from_xmpp_address:
        text = _remove_items(iocs['xmpp_addresses'], text)
    # even if we want to parse domain names from the xmpp_address, we don't want them also being caught as email addresses so we'll remove everything before the `@`
    else:
        text = _remove_xmpp_local_part(iocs['xmpp_addresses'], text)

    # complete email addresses
    iocs['email_addresses_complete'] = parse_complete_email_addresses(text)
    # simple email addresses
    iocs['email_addresses'] = parse_email_addresses(text)
    if not parse_domain_from_email_address:
        text = _remove_items(iocs['email_addresses_complete'], text)
        text = _remove_items(iocs['email_addresses'], text)
    # after parsing the email addresses, we need to remove the '[IPv6:' bit from any of the email addresses so that ipv6 addresses are not extraneously parsed
    text = _remove_items(['[IPv6:'], text)

    # cidr ranges
    iocs['ipv4_cidrs'] = parse_ipv4_cidrs(text)
    if not parse_address_from_cidr:
        text = _remove_items(iocs['ipv4_cidrs'], text)
    # iocs['ipv6_cidrs'] = parse_ipv6_cidrs(text)
    # if not parse_address_from_cidr:
    # text = _remove_items(iocs['ipv6_cidrs'], text)

    # file hashes
    if parse_imphashes:
        iocs['imphashes'] = parse_imphashes_(text)
        # remove the imphashes so they are not also parsed as md5s
        text = _remove_items(iocs['imphashes'], text)

    if parse_authentihashes:
        iocs['authentihashes'] = parse_authentihashes_(text)
        # remove the authentihashes so they are not also parsed as sha256s
        text = _remove_items(iocs['authentihashes'], text)

    loop = asyncio.get_event_loop()
    iocs['domains'], iocs['ipv4s'], iocs['ipv6s'], iocs['sha512s'], iocs['sha256s'], iocs['sha1s'], iocs['md5s'], iocs['ssdeeps'], iocs['asns'], iocs['cves'], iocs['registry_key_paths'], iocs['google_adsense_publisher_ids'], iocs['google_analytics_tracker_ids'], iocs['bitcoin_addresses'], iocs['mac_addresses'], iocs['user_agents'], iocs['file_paths'], iocs['phone_numbers'] = loop.run_until_complete(
        asyncio.gather(
            parse_domain_names(text),
            parse_ipv4_addresses(text),
            parse_ipv6_addresses(text),
            parse_sha512s(text),
            parse_sha256s(text),
            parse_sha1s(text),
            parse_md5s(text),
            parse_ssdeeps(text),
            parse_asns(text),
            parse_cves(text),
            parse_registry_key_paths(text),
            parse_google_adsense_ids(text),
            parse_google_analytics_ids(text),
            parse_bitcoin_addresses(text),
            parse_mac_addresses(text),
            parse_user_agents(text),
            parse_file_paths(text),
            parse_phone_numbers(text)
        )
    )

    return iocs
