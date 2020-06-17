import asyncio
from aiohttp import ClientSession,CookieJar,Fingerprint,ClientTimeout

from binascii import a2b_hex
from urllib.parse import urlparse
import json
from time import time

from contextlib import AsyncExitStack, asynccontextmanager
import logging

logger = logging.getLogger('aioedgeos')

'''
Try every few minutes to see if we are still able to access the internface
and do a fresh login if we can't.
'''
async def _login_helper(edgeos,interval):
    try:
        while 1:
            if not await edgeos.is_logged_in():
                await edgeos.login(interval=0) # don't spawn a new task
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        pass

'''
Send the very non-statndard PING for the websocket
'''
async def _websocket_helper(ws, interval=30):
    try:
        while True:
            await asyncio.sleep(interval)
            await ws.send_str('{"CLIENT_PING"}')
    except asyncio.CancelledError:
        pass

'''
Helper to find dhcp mappings
'''
def find_subkey(data, keyname):
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        if key == keyname:
            yield value
        else:
            yield from find_subkey(value, keyname)
    return

'''
Return the object formatted in a way preferred by EdgeOS
'''
def json_compact(obj):
    return json.dumps(obj,separators=(',', ':'))


class EdgeOS:
    username = None
    password = None
    url = None
    ssl = None
    session = None
    tasks = {}
    stack = None

    def __init__(self, username, password, url, ssl=None, session_id=None):
        self.username = username
        self.password = password
        self.url = url
        self.ssl = ssl
        self.session = None
        self.session_id = None
        self.headers = { 'Content-type': 'application/json' }
        self.cookies = { }
        self.sysdata = { 'ping-data': {} }
        if session_id:
            self.session_id = session_id
            self.cookies['beaker.session.id'] = session_id

    async def setup(self):
        self.stack = AsyncExitStack()
        self.stack.push_async_callback(EdgeOS.close, self)
        if not self.session:
            # If no session provided create our own, push on stack to make sure it's cleaned up later
            self.session = await self.stack.enter_async_context(
                    ClientSession(cookie_jar=CookieJar(unsafe=True), raise_for_status=True, timeout=ClientTimeout(15)))
        await self.login(interval=120)

    async def close(self):
        for key,value in self.tasks.items():
            logger.debug(f"DURING EXIT CLOSING {key}")
            try:
                value.cancel()
                await value
            except Exception as e:
                logger.warning(f"error canceling {key} got exception {e}")

    async def __aenter__(self):
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.stack.aclose()

    async def add_task(self, name, task):
        if self.tasks.get(name, None):
            logger.debug(f"PREMATURELY CLOSING {name}")
            old = self.tasks[name]
            try:
                old.cancel()
                await old
            except Exception as e:
                logger.warning(f"WHILE CANCELING {name} got exception {e}")
        self.tasks[name] = task

    async def is_logged_in(self):
        try:
            if await self.sys_info() != None:
                return True
        except:
            pass
        return False

    async def login(self, interval=120):
        if self.username and self.password and not await self.is_logged_in():
            async with self.session.post(f'{self.url}',
                                         data={'username':self.username, 'password': self.password}, 
                                         ssl=self.ssl) as resp:
                try:
                    s_id = self.session.cookie_jar.filter_cookies(self.url)['beaker.session.id'].value
                    token = self.session.cookie_jar.filter_cookies(self.url)['X-CSRF-TOKEN'].value
                    self.headers = { 'X-CSRF-TOKEN': token }
                    self.session_id = s_id
                    self.cookies['beaker.session.id'] = s_id
                    logger.debug("New seesion ending in {}".format(s_id[:4]))
                except Exception as e:
                    raise Exception(f"LOGIN ERROR {e}")
        # Should we stay logged in?
        if interval > 0:
            await self.add_task('login',asyncio.create_task(_login_helper(self,interval)))

    async def data(self, data_type):
        try:
            result = None
            async with self.session.get(f"{self.url}/api/edge/data.json?data={data_type}",
                                        ssl=self.ssl, 
                                        headers=self.headers, 
                                        raise_for_status=False, 
                                        cookies=self.cookies) as resp:
                if resp.status != 200:
                    return None
                result = await resp.json()
                if result.get('success', 0):
                    self.sysdata[data_type] = result.get('output',None)
                else:
                    return None
            return result
        except Exception as e:
            logging.debug(f"exception in data {e}")
            return None

    async def data_every(self, data_type, interval):
        # self- registering task
        task = asyncio.current_task()
        if task:
            await self.add_task(data_type, task)
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
        async with self.session.get(f"{self.url}/api/edge/get.json",
                                    ssl=self.ssl,
                                    headers=self.headers,
                                    cookies=self.cookies) as resp:
            if resp.status != 200:
                return None
            temp = await resp.json()
            if temp.get('success', False):
                self.sysconfig = temp['GET']
                return temp['GET']
        return None

    async def ping(self, target='1.1.1.1', count=3, size=100):
        ret = ''
        init = {'SUBSCRIBE': [{ 'name': 'ping-feed', 'sub_id': f'ping-{target}', 'target': target, 'count': count, 'size': size }]}
        async for payload in self._ws(init=init, keepalive=False, timeout=15):
            ret += payload[f'ping-{target}']
            if f"--- {target} ping statistics ---" in ret:
                self.sysdata['pinglast'] = ret
                return self.process_ping(ret, target)
                

    def process_ping(self, output, target):
        data = { target: { 'time': time() }}
        for line in output.splitlines():
            if 'packets transmitted' in line:
                sent, _, _, recv, *_ = line.split()
                data[target]['sent'] = int(sent)
                data[target]['lost'] = int(sent)-int(recv)
                continue
            if 'min/avg/max/mdev' in line:
                _, dat = line.split("=")
                dat = dat.split()[0]
                pdat = [float(x) for x in dat.split('/')]
                data[target]['min'] = pdat[0]
                data[target]['avg'] = pdat[1]
                data[target]['max'] = pdat[2]
                data[target]['mdev'] = pdat[3]
                        
        self.sysdata['ping-data'].update(data)
        return data

    async def ping_every(self, interval=120, target='1.1.1.1', **kwargs):
        # self- registering task
        task = asyncio.current_task()
        if task:
            await add_taks(f'ping-{target}-every', task)
        try:
            while True:
                await self.ping(target, **kwargs)
                await asyncio.sleep(interval)
        except asyncio.CancelledError:
            pass

    async def background_stats(self, subs=["export", "discover","interfaces","system-stats","num-routes","config-change", "users"]):
        # self- registering task
        task = asyncio.current_task()
        if task:
            await self.add_task('stats', task)
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
                    logger.debug("Detected config change, refreshing config cache")
                    await self.config()
            except:
                pass
            yield payload

    async def _ws(self, init, keepalive=True, timeout=30):
        pinger = None
        foo = { 'UNSUBSCRIBE': [] }
        foo.update(init)

        while True:
            try:
                '''
                Make sure that before we launch the WebSocket we have a valid
                session id
                '''
                while True:
                    if await self.is_logged_in():
                        break
                    logger.warning("Session died, trying a manual login")
                    await asyncio.sleep(5)
                    await self.login(interval=0)

                async with self.session.ws_connect(f"{self.url}/ws/stats", headers=self.headers, ssl=self.ssl) as ws:
                    foo.update({'SESSION_ID': self.session_id })
                    bar = json_compact(foo)
                    await ws.send_str("{}\n{}".format(len(bar), bar))
                    pinger = asyncio.create_task(_websocket_helper(ws))
                    data = ''
                    while True:
                        msg =  await asyncio.wait_for(ws.receive_str(), timeout)
    
                        data += msg
    
                        temp1, temp2 = data.split('\n',1)
                        data_len = int(temp1)
                        while len(temp2) >= data_len:
                            try:
                                payload = json.loads(temp2[:data_len])
                                self.sysdata.update(payload)
                                yield payload
                            except Exception as e:
                                logger.error(f"{e!r}")
                                logger.error(f'bad payload {temp2[:data_len]}')
                            data = temp2[data_len:]
                            if len(data) < 4: break
                            temp1, temp2 = data.split('\n',1)
                            data_len = int(temp1)
            except TypeError as e:
                # We got something that wasn't a string
                # bail and try again
                pass
            except asyncio.CancelledError as err:
                return
            except Exception as err:
                logger.warning(f"ws err {err!r}")
                if not keepalive:
                    return
            finally:
                # must cancel the task we started here so it doesn't get lost
                try:
                    if pinger:
                        pinger.cancel()
                        await pinger
                except Exception as e:
                    pass


