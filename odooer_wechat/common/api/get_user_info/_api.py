from yarl import URL
from ...const import APP_SECURE_SCHEME, BASE_HOST
from ...request import get_response
from ._classdef import WxUserInfo


async def request(session, access_token: str, openid: str) -> WxUserInfo:
    response = await get_response(session, URL.build(scheme=APP_SECURE_SCHEME, host=BASE_HOST, path='/cgi-bin/user/info'), {
        'access_token': access_token,
        'openid': openid,
        'lang': 'zh_CN'
    })
    print(response)
    return WxUserInfo(response)
