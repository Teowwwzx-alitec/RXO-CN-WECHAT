from collections import OrderedDict


class InfoCache(object):
    """
    数据缓存
    """
    __slots__ = []

    _fname2fid = OrderedDict()
    _fid2fname = OrderedDict()

    @classmethod
    def get_fid(cls, fname: str) -> int:
        """
        通过名称获取id
        """
        return cls._fname2fid.get(fname, '')

    @classmethod
    def get_fname(cls, fid: int) -> str:
        """
        通过id获取名称

        Args:
            fid (int): id

        Returns:
            str: 该贴吧的贴吧名
        """

        return cls._fid2fname.get(fid, '')

    @classmethod
    def add_forum(cls, fname: str, fid: int) -> None:
        """
        将名与id的映射关系添加到缓存

        Args:
            fname (str): 名称
            fid (int): id
        """

        if len(cls._fname2fid) == 128:
            cls._fname2fid.popitem(last=False)
            cls._fid2fname.popitem(last=False)

        cls._fname2fid[fname] = fid
        cls._fid2fname[fid] = fname
