# -*- coding: utf-8 -*-

from odoo import fields, models


class ResConfigSettings(models.TransientModel):
    _inherit = "res.config.settings"

    lark_login_appid = fields.Char(
        config_parameter="odoo_lark_login.appid", string="飞书 AppID"
    )
    lark_login_appsecret = fields.Char(
        config_parameter="odoo_lark_login.appsecret", string="飞书 AppSecret"
    )
    lark_login_return_url = fields.Char(
        config_parameter="odoo_lark_login.return_url",
        string="飞书 Return URL",
        help="授权回调域 url: /lark/login",
    )
    lark_login_bind_url = fields.Char(
        config_parameter="odoo_lark_login.bind_url",
        string="飞书 Bind URL",
        help="授权回调域 url: /lark/bind",
    )
    lark_login_token = fields.Char(
        config_parameter="odoo_lark_login.token",
        string="飞书 Token",
        help="用于服务器验证的 Token（如果需要）",
    )
