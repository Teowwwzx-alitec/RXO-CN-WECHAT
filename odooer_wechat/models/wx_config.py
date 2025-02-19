# -*- coding: utf-8 -*-
import string
import random
from ..common import wx_entry

try:
    from secrets import choice
except ImportError:
    from random import choice

from odoo import models, fields, api


class WxConfig(models.Model):
    _name = 'wx.config'
    _description = u'公众号配置'

    def _generate_token(self, length=''):
        if not length:
            length = random.randint(3, 32)
        length = int(length)
        assert 3 <= length <= 32
        letters = string.ascii_letters + string.digits
        return ''.join(choice(letters) for _ in range(length))

    name = fields.Char('名称')
    wx_appid = fields.Char('AppId')
    wx_secret = fields.Char('AppSecret')

    wx_url = fields.Char('URL', readonly=True, compute='_compute_wx_url', help='复制到公众号官方后台')
    wx_token = fields.Char('Token', default=_generate_token)
    wx_aeskey = fields.Char('EncodingAESKey', default='')

    reply = fields.Char(string='关注回复', default='欢迎关注！')

    def write(self, vals):
        result = super().write(vals)
        wx_entry.WxEntry().init(self.env, from_ui=True)
        return result

    def _compute_wx_url(self):
        objs = self
        for self in objs:
            base_url = self.env['ir.config_parameter'].sudo().get_param('web.base.url')
            self.wx_url = '{}/wx_handler'.format(base_url)

    @api.model
    def get_cur(self):
        return self.env.ref('odooer_wechat.wx_config_data_1')
