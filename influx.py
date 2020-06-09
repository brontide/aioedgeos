
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
ROUTER_SSL      = os.environ.get('ROUTER_SSL', True) # Default to enforcing ssl
INFLUX_HOST     = os.environ['INFLUX_HOST']
INFLUX_PORT     = os.environ.get('INFLUX_PORT', 8086)
INFLUX_DB       = os.environ['INFLUX_DB']

from aiohttp import Fingerprint
from binascii import a2b_hex

ssl_check = True
if len(ROUTER_SSL) == 64:
    # presume this is a fingerprint
    ssl_check = Fingerprint(a2b_hex(ROUTER_SSL))
elif ROUTER_SSL in [ 'no', 'false', 'NO', 'FALSE', 'False' ]:
    ssl_cehck = False

from aioedgeos import *
from time import time
import asyncio
from pprint import pprint

from aioinflux import *
from typing import NamedTuple

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
    ip2mac1 = ip2mac
    return ip2mac

def leases_extract(leases):
    ip2mac = {}
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
    global ip2mac2
    ip2mac2 = ip2mac
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


async def main_loop():
    async with EdgeOS(ROUTER_USERNAME,
                        ROUTER_PASSWORD,
                        ROUTER_URL,
                        ssl=ssl_check) as router, InfluxDBClient(INFLUX_HOST, INFLUX_PORT, database=INFLUX_DB) as client:

        await router.config()
        hostname = router.sysconfig['system']['host-name']
        print(f"Using router - {hostname}")

        config_extract_map(router.sysconfig)
        await router.dhcp_leases()
        leases_extract(router.sysdata['dhcp_leases'])
        asyncio.create_task(dhcp_refresh_loop(router))

        await client.create_database(INFLUX_DB)

        async for payload in router.stats():
            try:
                for key, value in payload.items():
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


asyncio.run(main_loop())

#def process_users(x):
#    json = []
#    for key, value in x.items():
#        temp = {
#                'measurement': 'user-count',
#                'tags': {
#                    'key': key
#                    },
#                'fields': {
#                    'value': len(value)
#                    }
#                }
#        if not is_dup(temp):
#            json.append(temp)
#        if key == 'l2tp':
#            for vpn in value:
#                for user, stuff in vpn.items():
#                    ip2name[stuff['remote-ip']] = "{}-{}".format(user, stuff['interface'])
#    return json
#
#while True:
#    if not s:
#        try:
#            s = edgeos_web(edgeos_url, username=username,password=password, verify=False)
#            s.login()
#            sleep(2)
#            ews = s.create_websocket()
#            ews.subscribe(subs=['interfaces','system-stats','export', 'users'])
#        except:
#            pass
#    try:
#        x = ews.next()
#        if 'system-stats' in x:
#            json = process_system_stats(x['system-stats'])
#            while not client.write_points(json, tags=default_tags):
#                sleep(1)
#            #print("S", end="", flush=True)
#        elif 'interfaces' in x:
#            json = process_interfaces(x['interfaces'])
#            while not client.write_points(json, tags=default_tags):
#                sleep(1)
#            #print("I", end="", flush=True)
#        elif 'export' in x:
#            json = process_export(x['export'])
#            while not client.write_points(json, tags=default_tags):
#                sleep(1)
#            #print("X", end="", flush=True)
#        elif 'users' in x:
#            json = process_users(x['users'])
#            while not client.write_points(json, tags=default_tags):
#                sleep(1)
#            #print("U", end="", flush=True)
#        else:
#            pass
#            #print(x)
#    except Exception as e:
#        #raise
#        print(f"Exception caught {e}")
#        s = None
#        sleep(5)
#        continue
