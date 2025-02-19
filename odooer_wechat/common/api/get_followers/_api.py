from yarl import URL
from ...const import APP_SECURE_SCHEME, BASE_HOST
from ...request import get_response
from ._classdef import Followers


async def request(session, access_token: str, next_openid: str) -> Followers:
    response = await get_response(session, URL.build(scheme=APP_SECURE_SCHEME, host=BASE_HOST, path="/cgi-bin/user/get"), {
        "access_token": access_token,
        "next_openid": next_openid
    })
    return Followers(response)
