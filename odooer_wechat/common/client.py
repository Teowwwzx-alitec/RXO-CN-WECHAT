import json
from datetime import timedelta
from yarl import URL
from urllib import parse
from .const import WX_TEMPLATE_SYS_ID, WX_TEMPLATE_ORDER_ID, WX_API_PREFIX, WX_TEMPLATE_ORDER_SYS_ID
from .helper import handle_exception, is_portrait
from .request import create_session, init_session, close_session, get_response, post_response
from .api import (
    # login,
    get_followers,
    get_access_token,
    get_user_info,
    post_message,
)

from .helper import TokenStore
from odoo import fields


class WxClient(object):
    '''
    基于 aiohttp 的微信公众号 API 接口客户端，仅实现小部分 API
    使用全部api, 可使用 wechatpy 或 werobot 替代。

    使用示例：
        wx_client = client_instance(wx_appid, wx_secret)
        loop = wx_client.loop
        ret = loop.run_until_complete(self.async_get_user_info(self.openid, wx_client))
    '''

    __slots__ = [
        '_app_id',
        '_secret',
        '_token_store',
        '_session',
        '_loop',
    ]

    def __init__(self, app_id, secret):
        self._app_id = app_id
        self._secret = secret
        self._token_store = TokenStore(secret)  # 不适合多线程
        self._session, self._loop = init_session()

    # async def __aenter__(self) -> "WxClient":
    #     return self

    # async def __aexit__(self, exc_type=None, exc_val=None, exc_tb=None) -> None:
    #     print("close _session")
    #     await close_session(self._session)

    async def close(self):
        await close_session(self._session)

    @handle_exception(bool)
    async def get_followers(self) -> get_followers.Followers:  # TODO 用户多需多次获取
        token = await self.latest_token()
        return await get_followers.request(self._session, token, '')

    @handle_exception(bool)
    async def get_user_info(self, openid: str) -> get_user_info.WxUserInfo:
        token = await self.latest_token()
        return await get_user_info.request(self._session, token, openid)

    @handle_exception(bool)
    async def get_token(self) -> get_access_token.AccessToken:
        return await get_access_token.request(self._session, self._app_id, self._secret)

    @handle_exception(bool)
    async def post_sys_message(self, openid, message):
        print(openid)
        token = await self.latest_token()
        data = {
            'touser': openid,
            'template_id': WX_TEMPLATE_SYS_ID,
            'data': {
                'thing2': {
                    'value': message,
                },
                'time3': {
                    'value': (fields.Datetime.now() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M'),
                }
            }
        }
        await post_message.request(self._session, token, data)

    @handle_exception(bool)
    async def post_order_message(self, token, openid, order_no, product, price, appid, pagepath):
        if not token:
            token = await self.latest_token()
        data = {
            'touser': openid,
            'template_id': WX_TEMPLATE_ORDER_ID,
            'miniprogram': {
                'appid': appid,
                'pagepath': pagepath,
            },
            'data': {
                'character_string8': {
                    'value': order_no,
                },
                'amount11': {
                    'value': str(price),
                },
                'thing6': {
                    'value': product,
                }
            }
        }
        await post_message.request(self._session, token, data)

    @handle_exception(bool)
    async def post_order_sys_message(self, token, openid, order_no, product, price, customer):
        if not token:
            token = await self.latest_token()
        data = {
            'touser': openid,
            'template_id': WX_TEMPLATE_ORDER_SYS_ID,
            'data': {
                'character_string9': {
                    'value': order_no,
                },
                'thing7': {
                    'value': product,
                },
                'amount8': {
                    'value': str(price),
                },
                'thing2': {
                    'value': customer,
                },
            }
        }
        await post_message.request(self._session, token, data)

    @handle_exception(bool)
    async def update_remark(self, openid, remark):
        '''更新用户备注'''
        url = WX_API_PREFIX + '/user/info/updateremark?access_token=' + await self.latest_token()
        ret = await post_response(self._session, url, json=None, data=json.dumps({
            'openid': openid,
            'remark': remark  # 直接 json= 传输乱码
        }, ensure_ascii=False))
        return ret

    @handle_exception(bool)
    async def get_industry(self):
        '''所属行业'''
        industry = await get_response(self._session, URL(WX_API_PREFIX) / 'template/get_industry', {
            'access_token': await self.latest_token(),
        })
        return industry

    @handle_exception(bool)
    async def get_templates(self):
        '''消息模板列表'''
        templates = await get_response(self._session, URL(WX_API_PREFIX) / 'template/get_all_private_template', {
            'access_token': await self.latest_token(),
        })
        return templates

    async def refresh_token(self):
        '''优先从缓存读取 access_token'''
        current_token = self._token_store.get()
        if not current_token:
            token = await self.get_token()
            if token:
                self._token_store.save(token.access_token, token.expires_in)

    async def latest_token(self):
        await self.refresh_token()
        return self._token_store.get()

    @property
    def loop(self):
        return self._loop


client = None


def client_instance(app_id, secret):
    global client
    if not client:
        client = WxClient(app_id, secret)
    return client
