from typing import Mapping, Optional


class Followers(object):
    """
    关注者列表

    Attributes:
        total: 	关注该公众账号的总用户数
        count: 	拉取的OPENID个数，最大值为10000
        data: 	列表数据，OPENID的列表
        next_openid: 	拉取列表的最后一个用户的OPENID
    """

    __slots__ = [
        '_total',
        '_count',
        '_data',
        '_next_openid',
    ]

    def __init__(self, data_map: Optional[Mapping] = None) -> None:
        if data_map:
            self._total = int(data_map['total'])
            self._count = int(data_map['count'])
            self._data = data_map['data']
            self._next_openid = data_map['next_openid']
        else:
            self._total = 0
            self._count = 0
            self._data = []
            self._next_openid = ''

    @property
    def total(self) -> int:
        return self._total

    @property
    def count(self) -> int:
        return self._count

    @property
    def data(self) -> list:
        return self._data
    
    @property
    def next_openid(self) -> str:
        return self._next_openid