#!/usr/bin/env python3 

########################
#
# Config items 
#
########################
from dotenv import load_dotenv
load_dotenv()
import os

ROUTER_USERNAME = os.environ['ROUTER_USERNAME']
ROUTER_PASSWORD = os.environ['ROUTER_PASSWORD']
ROUTER_URL      = os.environ['ROUTER_URL']
ROUTER_SSL      = os.environ.get('ROUTER_SSL', 'f'*64).lower() # Default to enforcing ssl
INFLUX_HOST     = os.environ['INFLUX_HOST']
INFLUX_PORT     = os.environ.get('INFLUX_PORT', 8086)
INFLUX_DB       = os.environ['INFLUX_DB']
INFLUX_USERNAME = os.environ.get('INFLUX_USERNAME',None)
INFLUX_PASSWORD = os.environ.get('INFLUX_PASSWORD',None)
PING_TARGET     = os.environ.get('PING_TARGET', '1.1.1.1')
PING_COUNT      = int(os.environ.get('PING_COUNT', 3))
PING_SIZE       = int(os.environ.get('PING_SIZE', 50))
PING_INTERVAL   = int(os.environ.get('PING_INTERVAL', 120))

import aiohttp
from binascii import a2b_hex, b2a_hex

ssl_check = True
if isinstance(ROUTER_SSL, str) and len(ROUTER_SSL) == 64:
    # presume this is a fingerprint
    ssl_check = aiohttp.Fingerprint(a2b_hex(ROUTER_SSL))
elif ROUTER_SSL in [ 'no', 'false']:
    ssl_check = False
elif ROUTER_SSL in [ 'yes', 'true']:
    ssl_check = True
else:
    raise Exception(f"ROUTER_SSL {ROUTER_SSL} is invalid")

influx_auth = {}
if INFLUX_USERNAME or INFLUX_PASSWORD:
    influx_auth.update({
        'username': INFLUX_USERNAME,
        'password': INFLUX_PASSWORD,
        })

from aioedgeos import *
from time import time
import asyncio
from pprint import pprint
from contextlib import AsyncExitStack

from aioinflux import *
from typing import NamedTuple

import logging
logging.basicConfig(format='%(asctime)s:%(levelname)s:%(name)s:%(message)s', level=logging.DEBUG)

@lineprotocol
class SystemStats(NamedTuple):
    router: TAG
    cpu: INT
    mem: INT
    uptime: INT

@lineprotocol
class Interfaces(NamedTuple):
    router: TAG
    ifname: TAG
    rx_packets: INT
    rx_bytes: INT
    rx_errors: INT
    rx_dropped: INT
    tx_packets: INT
    tx_bytes: INT
    tx_errors: INT
    tx_dropped: INT

if_fields = [
    'rx_packets', 'rx_bytes', 'rx_errors', 'rx_dropped', 
    'tx_packets', 'tx_bytes', 'tx_errors', 'tx_dropped', 
]

def process_interfaces(value, hostname):
    for interface, x in value.items():
        datapoint = Interfaces(router=hostname,
                ifname=interface,
                **dict((field_name, int(x['stats'][field_name])) for field_name in if_fields)
                )
        yield datapoint

@lineprotocol
class Clients(NamedTuple):
    router: TAG
    num_active: INT

@lineprotocol
class DPI(NamedTuple):
    router: TAG
    client_id: TAG
    client_name: TAG
    dpi: TAG
    rx_bytes: INT
    tx_bytes: INT


ip2mac1 = {}
ip2mac2 = {}

def config_extract_map(config):
    ip2mac = {}
    for mapping in find_subkey(config, 'static-mapping'):
        for name, value in mapping.items():
            ip2mac[value['ip-address']] = {
                'ip': value['ip-address'],
                'mac': value['mac-address'],
                'name': name,
                }
    global ip2mac1
    ip2mac1.update(ip2mac)
    return ip2mac

def leases_extract(leases):
    ip2mac = {}
    try:
        for lan, lan_lease in leases['dhcp-server-leases'].items():
            if not isinstance(lan_lease, dict): continue
            for ip, value in lan_lease.items():
                name = value['client-hostname']
                if len(name) == 0:
                    name = "-"
                ip2mac[ip] = {
                    'ip': ip,
                    'mac': value['mac'],
                    'name': name
                    }
    except:
        pass
    global ip2mac2
    ip2mac2.update(ip2mac)
    return ip2mac

def best_id_name(ip):
    if ip in ip2mac1:
        return ip2mac1[ip]['mac'], ip2mac1[ip]['name']
    if ip in ip2mac2:
        return ip2mac2[ip]['mac'], ip2mac2[ip]['name']
    return ip, "UNK"

def process_export(value,hostname):
    datapoint = Clients(router=hostname, num_active=len(value))
    yield datapoint
    if not isinstance(value, dict): return
    for ip, dpi in value.items():
        oid, name = best_id_name(ip)
        for app, value in dpi.items():
            rx_bytes = int(value['rx_bytes'])
            tx_bytes = int(value['tx_bytes'])
            rx_rate = int(value['rx_rate'])
            tx_rate = int(value['tx_rate'])
            if rx_rate == 0 and tx_rate == 0: continue
            yield DPI(router=hostname, client_id=oid, client_name=name, dpi=app,
                        rx_bytes = rx_bytes,
                        tx_bytes = tx_bytes )
    return

@lineprotocol
class Users(NamedTuple):
    router: TAG
    user_type: TAG
    count: INT

def process_users(value, hostname):
    for user_type, value in value.items():
        yield Users(router=hostname, user_type=user_type, count=len(value))


async def dhcp_refresh_loop(router):
    try:
        while True:
            await router.dhcp_leases()
            leases_extract(router.sysdata['dhcp_leases'])
            await asyncio.sleep(600)
    except asyncio.CancelledError:
        pass

@lineprotocol
class Latency(NamedTuple):
    router: TAG
    target: TAG
    latency: FLOAT
    lost: INT

async def latency_loop(client,router, target, count, size, offset=0):
    await asyncio.sleep(offset)
    hostname = router.sysconfig['system']['host-name']
    try:
        while True:
            await router.ping(target=target, count=count, size=size)
            await client.write(Latency(router=hostname,
                                target=target,
                                latency=router.sysdata['ping-data'][target].get('avg', None),
                                lost=router.sysdata['ping-data'][target].get('lost', None)))
            await asyncio.sleep(PING_INTERVAL)
    except asyncio.CancelledError:
        pass
    except Exception as e:
        print(e)

async def main_loop():
    async with AsyncExitStack() as stack:
        try:
            ''' ROUTER SETUP '''
            logging.info(f"CONNECTING TO ROUTER {ROUTER_URL} with user {ROUTER_USERNAME}")
            router = await stack.enter_async_context(
                   EdgeOS(ROUTER_USERNAME, ROUTER_PASSWORD, ROUTER_URL, ssl=ssl_check))
            await router.config()
            hostname = router.sysconfig['system']['host-name']
            config_extract_map(router.sysconfig)
            await router.dhcp_leases()
            leases_extract(router.sysdata['dhcp_leases'])
            logging.info(f"CONNECTED TO ROUTER {hostname}")
            ''' INFLUX SETUP '''
            logging.info(f"CONNECTING TO INFLUX {INFLUX_HOST}:{INFLUX_PORT}/{INFLUX_DB}")
            client = await stack.enter_async_context(
                    InfluxDBClient(INFLUX_HOST, INFLUX_PORT, database=INFLUX_DB, **influx_auth))
            await client.create_database(INFLUX_DB)
            logging.info(f"CONNECTED TO INFLUX")

            logging.info("LAUNCHING DHCP SCRAPER")
            asyncio.create_task(dhcp_refresh_loop(router))
            '''
            For ping testing, let's breakdown the list into targets and make sure that
            we don't start pinging all of them at once by staggering them based on their
            position in the list
            '''
            targets = PING_TARGET.split('/')
            for i, target in enumerate(targets):
                offset = (i)*int(PING_INTERVAL/len(targets))
                logging.info(f"LAUNCHING LATENCY CHECK LOOP FOR {target} with offset {offset}")
                ping = asyncio.create_task(latency_loop(client,router, target, PING_COUNT, PING_SIZE, offset=offset))

            logging.info("STARTING MAIN WEBSOCKET LOOP")
            async for payload in router.stats():
                try:
                    for key, value in payload.items():
                        if not isinstance(value, dict):
                            logging.warning(f"{value} for {key} isn't a dict, would likely cause trouble in processing skipping")
                            continue
                        if key == 'system-stats':
                            datapoint = SystemStats( router=hostname,
                                                        **value )
                            await client.write(datapoint)
                        elif key == 'interfaces':
                            await client.write(process_interfaces(value, hostname))
                        elif key == 'export':
                            await client.write(process_export(value, hostname))
                        elif key == 'users':
                            await client.write(process_users(value, hostname))
                        elif key == 'config-change' and value['commit'] == 'ended':
                            ip2mac1 = config_extract_map(router.sysconfig)
                        else:
                            pass
                            #print(f"got {key} - ignoring for now")
                except:
                    raise
        except aiohttp.client_exceptions.ServerFingerprintMismatch as e:
            fphash = b2a_hex(e.got).decode()
            print(f'''
===============   TLS/SSL HASH MISMATCH ===============
Server replied with different fingerprint hash of {fphash}, it's likely you didn't setup the 
ssl for your router.  If this is the case please update your environment with the following.

ROUTER_SSL={fphash}
===============   TLS/SSL HASH MISMATCH ===============''')
        

print(f'''
================================================
ROUTER_USERNAME = {ROUTER_USERNAME}
ROUTER_PASSWORD = **HIDDEN**
ROUTER_URL      = {ROUTER_URL}
ROUTER_SSL      = {ROUTER_SSL}
 - ssl_check   -> {ssl_check}
INFLUX_HOST     = {INFLUX_HOST}
INFLUX_PORT     = {INFLUX_PORT}
INFLUX_DB       = {INFLUX_DB}
INFLUX_USERNAME = {INFLUX_USERNAME}
INFLUX_PASSWORD = **HIDDEN**
PING_TARGET     = {PING_TARGET}
PING_COUNT      = {PING_COUNT}
PING_SIZE       = {PING_SIZE}
PING_INTERVAL   = {PING_INTERVAL}
================================================
''')

asyncio.run(main_loop())
