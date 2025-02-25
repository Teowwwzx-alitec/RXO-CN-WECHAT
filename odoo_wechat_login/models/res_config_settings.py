# -*- coding: utf-8 -*-

from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    wechat_login_appid = fields.Char(
        config_parameter="odoo_wechat_login.appid", string="微信appid"
    )
    wechat_login_appsecret = fields.Char(
        config_parameter="odoo_wechat_login.appsecret", string="微信appsecret"
    )
    wechat_login_return_url = fields.Char(
        config_parameter="odoo_wechat_login.return_url",
        string="微信return_url",
        help="授权回调域url+/wechat/login",
    )
    wechat_login_bind_url = fields.Char(
        config_parameter="odoo_wechat_login.bind_url",
        string="微信bind_url",
        help="授权回调域url+/wechat/bind",
    )
    wechat_login_token = fields.Char(
        config_parameter="odoo_wechat_login.token",
        string="微信token",
        help="授权回调域url+/wechat/token",
    )
