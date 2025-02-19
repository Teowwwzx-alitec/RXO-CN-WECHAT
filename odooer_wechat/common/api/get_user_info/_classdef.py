from datetime import datetime
from typing import Mapping, Optional


class WxUserInfo(object):
    """
    用户基本信息(UnionID机制)

    Attributes:
        subscribe: 	用户是否订阅该公众号标识，值为0时，代表此用户没有关注该公众号，拉取不到其余信息。
        openid: 	用户的标识，对当前公众号唯一
        subscribe_time: 	用户关注时间，为时间戳。如果用户曾多次关注，则取最后关注时间
        unionid: 	只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段。
        remark: 	公众号运营者对粉丝的备注，公众号运营者可在微信公众平台用户管理界面对粉丝添加备注
        groupid: 	用户所在的分组ID（兼容旧的用户分组接口）
        tagid_list: 	用户被打上的标签ID列表
        subscribe_scene: 返回用户关注的渠道来源，ADD_SCENE_SEARCH 公众号搜索，ADD_SCENE_ACCOUNT_MIGRATION 公众号迁移，ADD_SCENE_PROFILE_CARD 名片分享，ADD_SCENE_QR_CODE 扫描二维码
        qr_scene: 	二维码扫码场景（开发者自定义）
        qr_scene_str: 	二维码扫码场景描述（开发者自定义）
    """

    __slots__ = [
        '_subscribe',
        '_openid',
        '_subscribe_time',
        '_unionid',
        '_remark',
        '_groupid',
        '_tagid_list',
        '_subscribe_scene',
        '_qr_scene',
        '_qr_scene_str',
    ]

    def __init__(self, data_map: Optional[Mapping] = None) -> None:
        if data_map:
            self._subscribe = bool(data_map['subscribe'])
            self._openid = data_map['openid']
            self._subscribe_time = data_map['subscribe_time']
            self._unionid = data_map['unionid'] if data_map.get('unionid') else ''
            self._remark = data_map['remark']
            self._groupid = int(data_map['groupid'])
            self._tagid_list = data_map['tagid_list']
            self._subscribe_scene = data_map['subscribe_scene']
            self._qr_scene = int(data_map['qr_scene'])
            self._qr_scene_str = data_map['qr_scene_str']

    @property
    def subscribe(self) -> bool:
        return self._subscribe
    
    @property
    def openid(self) -> str:
        return self._openid
    
    @property
    def subscribe_time(self) -> int:
        return self._subscribe_time
    
    @property
    def unionid(self) -> str:
        return self._unionid
    
    @property
    def remark(self) -> str:
        return self._remark
    
    @property
    def groupid(self) -> int:
        return self._groupid
    
    @property
    def tagid_list(self) -> list:
        return self._tagid_list
    
    @property
    def subscribe_scene(self) -> str:
        return self._subscribe_scene
  
    @property
    def qr_scene(self) -> int:
        return self._qr_scene
    
    @property
    def qr_scene_str(self) -> str:
        return self._qr_scene_str
    
    def get_values(self):
        return {
            'subscribe': self.subscribe,
            'openid': self.openid,
            'subscribe_time': datetime.fromtimestamp(self.subscribe_time),
            'unionid': self.unionid,
            'remark': self.remark,
            'groupid': self.groupid,
            'tagid_list': ','.join([str(i) for i in self.tagid_list]) if len(self.tagid_list) > 0 else '',
            'subscribe_scene': self.subscribe_scene,
            'qr_scene': self.qr_scene,
            'qr_scene_str': self.qr_scene_str,
        }
