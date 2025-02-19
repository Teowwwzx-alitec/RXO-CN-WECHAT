import aiohttp
import asyncio
import async_timeout
from .exception import ServerError


def create_session():
    conn = aiohttp.TCPConnector(ssl=False)
    return aiohttp.ClientSession(connector=conn)


def init_session():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    session = create_session()
    return session, loop


def check_response_error(data, error_code=0, error_msg_key='errmsg'):
    if code := int(data.get('errcode', 0)) != error_code:
        raise ServerError(code, data[error_msg_key])


async def get_response(session, url, params=None, timeout=10, response_callback=None):
    async with async_timeout.timeout(timeout):
        async with session.get(url, params=params) as response:
            if response_callback:
                return await response_callback(response)
            else:
                result = await response.json()
                check_response_error(result)
                return result


async def post_response(session, url, json, data=None, timeout=10,  response_callback=None):
    async with async_timeout.timeout(timeout):
        async with session.post(url, json=json, data=data) as response:
            if response_callback:
                return await response_callback(response)
            else:
                result = await response.json()
                check_response_error(result)
                return result


async def close_session(session):
    print('close_session')
    await session.close()
