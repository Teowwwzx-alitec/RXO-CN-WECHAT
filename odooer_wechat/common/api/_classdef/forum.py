
class Forum(object):
    """
    论坛

    Attributes:
        fid (int): id
        fname (str): 名称
    """

    __slots__ = [
        '_fid',
        '_fname',
    ]

    def _init(self, id: int, name: str) -> "Forum":
        self._fid = id
        self._fname = name
        return self

    def _init_null(self) -> "Forum":
        self._fid = 0
        self._fname = ''
        return self

    def __repr__(self) -> str:
        return str(
            {
                'fid': self._fid,
                'fname': self._fname,
            }
        )

    @property
    def fid(self) -> int:
        return self._fid

    @property
    def fname(self) -> str:
        return self._fname
