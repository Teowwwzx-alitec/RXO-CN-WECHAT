from yarl import URL
from ...const import APP_SECURE_SCHEME, BASE_HOST
from ...request import get_response
from ._classdef import AccessToken


async def request(session, appid: str, secret: str) -> AccessToken:
    response = await get_response(session, URL.build(scheme=APP_SECURE_SCHEME, host=BASE_HOST, path='/cgi-bin/token'), {
        'grant_type': 'client_credential',
        'appid': appid,
        'secret': secret
    })
    return AccessToken(response)
