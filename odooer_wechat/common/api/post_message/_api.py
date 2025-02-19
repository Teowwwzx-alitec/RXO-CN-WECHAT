import json
from typing import Optional
from yarl import URL
from ...const import APP_SECURE_SCHEME, BASE_HOST
from ...request import post_response


async def request(session, token: str, data: dict):
    response = await post_response(
        session,
        URL.build(scheme=APP_SECURE_SCHEME,
                  host=BASE_HOST,
                  path='/cgi-bin/message/template/send',
                  query={'access_token': token}),
        json=data
    )
    return response
