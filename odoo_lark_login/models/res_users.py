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

    def bind_to_lark(self):
        """Initiate Lark login binding."""
        self.ensure_one()
        appid = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appid")
        bind_url = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.bind_url")
        state = {
            "u": self.id,
            "d": self.env.cr.dbname,
            "redirect_uri": self.env["ir.config_parameter"].sudo().get_param("web.base.url") + "/",
        }

        params = dict(
            response_type="code",
            app_id=appid,
            redirect_uri=bind_url,
            scope="lark_login",
            # Base64-encode the state for URL transmission (and decode to UTF-8 string)
            state=base64.b64encode(simplejson.dumps(state).encode("utf-8")).decode("utf-8"),
        )
        # Construct the final Lark OAuth URL based on Lark's auth endpoint.
        url_token = "%s?%s" % (
            "https://open.larksuite.com/open-apis/authen/v1/index",
            url_encode(params),
        )
        return {
            "type": "ir.actions.act_url",
            "target": "self",
            "url": url_token,
        }

    @api.model
    def auth_oauth(self, provider, params):
        """Route the OAuth authentication based on the provider."""
        oauth_provider = self.env["auth.oauth.provider"].browse(int(provider))
        if "open.larksuite.com/open-apis/authen/v1/access_token" in oauth_provider.validation_endpoint:
            return self.auth_oauth_lark(oauth_provider, params)
        else:
            return super(ResUsers, self).auth_oauth(provider, params)

    @api.model
    def auth_oauth_lark(self, provider, params):
        """Authenticate via Lark OAuth and bind the account."""
        def gettoken(url, app_id, app_secret, code):
            url_token = "%s?app_id=%s&app_secret=%s&code=%s" % (url, app_id, app_secret, code)
            headers = {"Content-Type": "application/json"}
            response = requests.get(url_token, headers=headers)
            dict_data = response.json()
            # Lark returns code==0 on success.
            if dict_data.get("code") == 0:
                return dict_data["data"]
            else:
                raise AccessDenied(
                    "飞书获取access_token错误：code=%s, msg=%s"
                    % (dict_data.get("code"), dict_data.get("msg"))
                )

        app_id = provider.client_id
        app_secret = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appsecret")
        code = params.get("access_token", False)
        if not code:
            raise AccessDenied("飞书扫码错误：没有 code！")

        token_data = gettoken(provider.validation_endpoint, app_id, app_secret, code)

        # Assume that Lark returns the unique identifier as 'open_id'
        user_id = self.sudo().search(
            [("openid", "=", token_data.get("open_id"))],
            limit=1,
        )
        if not user_id:
            raise AccessDenied("用户绑定错误：open_id=%s" % token_data.get("open_id"))
        user_id.oauth_access_token = code

        return (self.env.cr.dbname, user_id.login, code)
