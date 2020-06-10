import asyncio
from aiohttp import ClientSession,CookieJar,Fingerprint,ClientTimeout

from binascii import a2b_hex
from urllib.parse import urlparse
import json
from time import time

async def _login_helper(edgeos,interval):
    try:
        while 1:
            if await edgeos.sys_info() == None:
                await edgeos.login(interval=0) # don't spawn a new task
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        pass

async def _websocket_helper(ws, interval=30):
    try:
        while True:
            await asyncio.sleep(interval)
            await ws.send_str('{"CLIENT_PING"}')
    except asyncio.CancelledError:
        pass

def find_subkey(data, keyname):
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        if key == keyname:
            yield value
        else:
            yield from find_subkey(value, keyname)
    return

class EdgeOS:
    username = None
    password = None
    url = None
    ssl = None
    session = None
    tasks = {}

    def __init__(self, username, password, url, ssl=None):
        self.username = username
        self.password = password
        self.url = url
        self.ssl = ssl
        self.session = None
        self.session_id = None
        self.headers = {}
        self.sysdata = {}

    async def setup(self):
        if not self.session:
            self.session = ClientSession(cookie_jar=CookieJar(unsafe=True), raise_for_status=True, timeout=ClientTimeout(15))
        await self.login(interval=120)

    async def close(self):
        if self.session:
            await self.session.close()
        for key,value in self.tasks.items():
            print(f"Canceling {key}")
            value.cancel()
            await value

    async def __aenter__(self):
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()

    async def login(self, interval=120):
        async with self.session.post(self.url, data={'username':self.username, 'password': self.password},ssl=self.ssl) as resp:
            try:
                print("good login")
                s_id = self.session.cookie_jar.filter_cookies(self.url)['PHPSESSID'].value
                token = self.session.cookie_jar.filter_cookies(self.url)['X-CSRF-TOKEN'].value
                self.headers = { 'X-CSRF-TOKEN': token }
                self.session_id = s_id
            except Exception as e:
                raise Exception(f"LOGIN ERROR {e}")
        # Should we stay logged in?
        if interval > 0:
            if self.tasks.get('login',None): 
                self.tasks['login'].cancel()
            self.tasks['login'] = asyncio.create_task(_login_helper(self,interval))

    async def data(self, data_type):
        try:
            result = None
            async with self.session.get(f"{self.url}/api/edge/data.json?data={data_type}", ssl=self.ssl, headers=self.headers) as resp:
                result = await resp.json()
                if result.get('success', 0):
                    self.sysdata[data_type] = result.get('output',None)
                else:
                    return None
            return result
        except Exception as e:
            print(e)
            return None

    async def data_every(self, data_type, interval):
        # self- registering task
        task = asyncio.current_task()
        if task:
            old = self.tasks.get(data_type, None)
            if old:
                old.cancel()
                await old
            self.tasks[data_type] = task
        try:
            while True:
                await self.data(data_type)
                await asyncio.sleep(interval)
        except asyncio.CancelledError as e:
            pass

    async def sys_info(self):
        return await self.data('sys_info')

    async def dhcp_leases(self):
        return await self.data('dhcp_leases')

    async def dhcp_stats(self):
        return await self.data('dhcp_stats')

    async def routes(self):
        return await self.data('routes')

    async def sys_info(self):
        return await self.data('sys_info')

    async def config(self):
        async with self.session.get(f"{self.url}/api/edge/get.json", ssl=self.ssl, headers=self.headers) as resp:
            temp = await resp.json()
            if temp.get('success', False):
                self.sysconfig = temp['GET']
                return temp['GET']
        return None

    async def ping(self, target='1.1.1.1', count=3, size=100):
        ret = ''
        init = {'SUBSCRIBE': [{ 'name': 'ping-feed', 'sub_id': 'ping1', 'target': target, 'count': count, 'size': size }]}
        async for payload in self._ws(init=init, keepalive=False, timeout=ClientTimeout(total=4)):
            ret += payload['ping1']
            if 'min/avg/max/mdev' in ret:
                self.sysdata['pinglast'] = ret
                self.process_ping()
                return ret

    def process_ping(self):
        for line in self.sysdata['pinglast'].splitlines():
            if 'min/avg/max/mdev' in line:
                #print(line)
                _, dat = line.split("=")
                dat = dat.split()[0]
                pdat = [float(x) for x in dat.split('/')]
                self.sysdata['ping-data'] = {
                        'time': time(),
                        'min': pdat[0],
                        'avg': pdat[1],
                        'max': pdat[2],
                        'mdev': pdat[3],
                        }

    async def ping_every(self, interval=120, **kwargs):
        # self- registering task
        task = asyncio.current_task()
        if task:
            old = self.tasks.get('ping-every', None)
            if old:
                old.cancel()
                await old
            self.tasks['ping-every'] = task
        try:
            while True:
                await self.ping(**kwargs)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass

    async def background_stats(self, subs=["export", "discover","interfaces","system-stats","num-routes","config-change", "users"]):
        # self- registering task
        task = asyncio.current_task()
        if task:
            old = self.tasks.get('stats', None)
            if old:
                old.cancel()
                await old
            self.tasks['stats'] = task
        try:
            async for payload in self.stats(subs):
                pass
        except asyncio.CancelledError:
            pass

    async def stats(self, subs=["export", "discover","interfaces","system-stats","num-routes","config-change", "users"], reload_on_change=True):
        if reload_on_change and ( not 'config-change' in subs ):
            subs.append('config-change')
        init = {'SUBSCRIBE': [{'name': x } for x in subs]}
        async for payload in self._ws(init=init):
            try:
                if reload_on_change and 'config-change' in payload and payload['config-change']['commit'] == 'ended':
                    asyncio.create_task(self.config())
            except:
                pass
            yield payload

    async def _ws(self, init, keepalive=True, timeout=None):
        pinger = None
        foo = { 'UNSUBSCRIBE': [] }
        foo.update(init)
        if not timeout:
            timeout = ClientTimeout(total=15)

        while True:
            try:
                async with self.session.ws_connect(f"{self.url}/ws/stats", headers=self.headers, ssl=self.ssl, timeout=timeout) as ws:
                    foo.update({'SESSION_ID': self.session_id })
                    bar = json.dumps(foo,separators=(',', ':'))
                    await ws.send_str("{}\n{}".format(len(bar), bar))
                    pinger = asyncio.create_task(_websocket_helper(ws))
                    data = ''
                    async for msg in ws:
    
                        data += msg.data
    
                        temp1, temp2 = data.split('\n',1)
                        data_len = int(temp1)
                        while len(temp2) >= data_len:
                            try:
                                payload = json.loads(temp2[:data_len])
                                self.sysdata.update(payload)
                                yield payload
                            except Exception as e:
                                print(f"{e!r}")
                                print(f'bad payload {temp2[:data_len]}')
                            data = temp2[data_len:]
                            if len(data) < 4: break
                            temp1, temp2 = data.split('\n',1)
                            data_len = int(temp1)
            # KeyboardInterrupt is pushed as CancelledError
            except asyncio.CancelledError as err:
                return
            except Exception as err:
                if not keepalive:
                    return
                print(f"Got exception in stats {err!r} sleeping 5 seconds")
            finally:
                # must cancel the task we started here so it doesn't get lost
                if pinger:
                    pinger.cancel()
                    await pinger
            await asyncio.sleep(5)


#async def main():
#    dumont = None
#    try:
#        dumont = EdgeOS(username,password,edgeos_url,ssl=fp_check)
#        await dumont.login(interval=10)
#        print(await dumont.routes())
#        #print(await dumont.dhcp_stats())
#        #print(await dumont.dhcp_leases())
#        #print(await dumont.sys_info())
#        #print(await dumont.config())
#        print(await dumont.ping(target='1.1.1.1',count=5,size=100))
#        async for payload in dumont.stats():
#            print(payload.keys())
#    except asyncio.CancelledError:
#        pass
#    finally:
#        print(dumont.sysdata.keys())
#        await dumont.close()
#
#try:
#    asyncio.run(main())
#except KeyboardInterrupt:
#    pass
