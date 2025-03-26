# -*- coding: utf-8 -*-

import logging

import requests
import base64
import simplejson
from werkzeug.urls import url_encode
from odoo import _, api, fields, models
from odoo.exceptions import AccessDenied, ValidationError

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    openid = fields.Char(string="Openid")
    # wechat_nickname = fields.Char(string='微信昵称')

    # def bind_to_wechat(self):
    #     self.ensure_one()
    #     appid = self.env["ir.config_parameter"].sudo().get_param("odoo_wechat_login.appid")
    #     bind_url = (
    #         self.env["ir.config_parameter"].sudo().get_param("odoo_wechat_login.bind_url")
    #     )
    #     state = {
    #         "u": self.id,
    #         "d": self.env.cr.dbname,
    #         "redirect_uri": self.env["ir.config_parameter"]
    #         .sudo()
    #         .get_param("web.base.url")
    #         + "/",
    #     }
    #
    #     params = dict(
    #         response_type="code",
    #         appid=appid,
    #         # 因为一个应用只能配置一个域名下的回调地址，所以这块设置了一个静态值，由此静态值分发请求
    #         redirect_uri=bind_url,
    #         scope="snsapi_login",
    #         # 使用base64加密的形式进行传输，普通的json会被微信处理成乱码
    #         state=base64.b64encode(simplejson.dumps(state).encode("utf-8")),
    #     )
    #     # 最终的微信登入请求链接
    #     url_token = "%s?%s" % (
    #         "https://open.weixin.qq.com/connect/qrconnect",
    #         url_encode(params),
    #     )
    #     return {
    #         "type": "ir.actions.act_url",
    #         "target": "self",
    #         "url": url_token,
    #     }
    #
    # @api.model
    # def auth_oauth(self, provider, params):
    #     oauth_provider = self.env["auth.oauth.provider"].browse(int(provider))
    #     if "api.weixin.qq.com/sns/oauth2" in oauth_provider.validation_endpoint:
    #         return self.auth_oauth_wechat_sns(oauth_provider, params)
    #     else:
    #         return super(ResUsers, self).auth_oauth(provider, params)
    #
    # @api.model
    # def auth_oauth_wechat_sns(self, provider, params):
    #     def gettoken(url, appid, secret, code):
    #         url_token = (
    #             "%s?appid=%s&secret=%s&code=%s&grant_type=authorization_code"
    #             % (url, appid, secret, code)
    #         )
    #         headers = {"Content-Type": "application/json"}
    #         response = requests.get(url_token, headers=headers)
    #         dict_data = response.json()
    #         errcode = dict_data.get("errcode", 0)
    #         if errcode == 0:
    #             return dict_data
    #         else:
    #             raise AccessDenied(
    #                 "微信获取access_token错误：err_code=%s, err_msg=%s"
    #                 % (dict_data["errcode"], dict_data["errmsg"])
    #             )
    #
    #     appid = provider.client_id
    #     secret = (
    #         self.env["ir.config_parameter"].sudo().get_param("odoo_wechat_login.appsecret")
    #     )
    #     code = params.get("access_token", False)
    #     if not code:
    #         raise AccessDenied("微信扫码错误：没有 code！")
    #
    #     dict_data = gettoken(provider.validation_endpoint, appid, secret, code)
    #
    #     user_id = self.sudo().search(
    #         [("openid", "=", dict_data["openid"])],
    #         limit=1,
    #     )
    #     if not user_id:
    #         raise AccessDenied("用户绑定错误：openid=%s" % (dict_data["openid"]))
    #     user_id.oauth_access_token = code
    #
    #     # unionid = dict_data.get("unionid", '')
    #     # if unionid:
    #     #     headers = {"Content-Type": "application/json"}
    #     #     user_url = "%s?access_token=%s&openid=%s" % (
    #     #         provider.data_endpoint,
    #     #         dict_data["access_token"],
    #     #         dict_data["openid"],
    #     #     )
    #     #     response = requests.get(user_url, headers=headers)
    #     #     dict_user = response.json()
    #     #     errcode = dict_user.get("errcode", 0)
    #     #
    #     #     _logger.warning("------------------" + str(dict_user))
    #     #     if errcode == 0:
    #     #         if user_id.employee_ids:
    #     #             values = {
    #     #                 "name": dict_user["nickname"],
    #     #                 "gender": "male" if dict_user["gender"] == 1 else "female",
    #     #             }
    #     #             user_id.employee_ids.sudo().write(values)
    #     #     else:
    #     #         raise AccessDenied(
    #     #             "微信获取访问用户身份错误：err_code=%s, err_msg=%s"
    #     #             % (dict_user["errcode"], dict_user["errmsg"])
    #     #         )
    #
    #     return (self.env.cr.dbname, user_id.login, code)
