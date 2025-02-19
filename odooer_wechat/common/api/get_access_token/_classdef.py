from typing import Mapping, Optional


class AccessToken(object):
    """
    AccessToken

    Attributes:
        access_token:str 	获取到的凭证
        expires_in:int 	凭证有效时间，单位：秒
    """

    __slots__ = [
        '_access_token',
        '_expires_in',
    ]

    def __init__(self, data_map: Optional[Mapping] = None) -> None:
        if data_map:
            self._access_token = data_map['access_token']
            self._expires_in = int(data_map['expires_in'])
        else:
            self._access_token = ''
            self._expires_in = 0

    @property
    def expires_in(self) -> int:
        return self._expires_in
    
    @property
    def access_token(self) -> str:
        return self._access_token