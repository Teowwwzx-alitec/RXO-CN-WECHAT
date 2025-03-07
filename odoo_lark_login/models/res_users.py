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

    @api.model
    def auth_oauth_lark(self, provider, params):
        """
        Handles Lark OAuth:
          1. Exchange 'code' for an 'access_token' via POST to /authen/v1/access_token.
          2. Retrieve user info from /authen/v1/user_info using Bearer <access_token>.
          3. Bind or find the user in Odoo by open_id.
        """

        def get_access_token(token_url, app_id, app_secret, code):
            """
            Calls Lark's /authen/v1/access_token endpoint with a JSON POST body.
            Returns (access_token, expires_in).
            """
            headers = {"Content-Type": "application/json"}
            payload = {
                "grant_type": "authorization_code",
                "code": code,
                "app_id": app_id,
                "app_secret": app_secret,
            }
            response = requests.post(token_url, json=payload, headers=headers)
            _logger.info("Lark token response: %s", response.text)
            token_res = response.json()
            if token_res.get("code") == 0:
                # "data" should contain "access_token", "token_type", "expires_in"
                data = token_res.get("data", {})
                return data.get("access_token"), data.get("expires_in")
            else:
                raise AccessDenied(
                    "飞书获取access_token错误：code=%s, msg=%s"
                    % (token_res.get("code"), token_res.get("msg"))
                )

        def get_user_info(access_token):
            """
            Calls Lark's /authen/v1/user_info endpoint with the Bearer token.
            Returns a dict containing open_id, union_id, email, etc.
            """
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            }
            user_info_url = "https://open.larksuite.com/open-apis/authen/v1/user_info"
            response = requests.get(user_info_url, headers=headers)
            _logger.info("Lark user_info response: %s", response.text)
            user_res = response.json()
            if user_res.get("code") == 0:
                return user_res.get("data", {})
            else:
                raise AccessDenied(
                    "飞书获取用户信息错误：code=%s, msg=%s"
                    % (user_res.get("code"), user_res.get("msg"))
                )

        # 1) Extract code from 'params' (in Odoo’s default auth_oauth flow, 'code' is in 'access_token')
        app_id = provider.client_id
        app_secret = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appsecret")
        code = params.get("access_token")  # We stored the code in 'access_token'
        if not code:
            raise AccessDenied("飞书扫码错误：没有 code！")

        # 2) Exchange code for access token
        token_url = provider.validation_endpoint  # e.g. "https://open.larksuite.com/open-apis/authen/v1/access_token"
        lark_access_token, expires_in = get_access_token(token_url, app_id, app_secret, code)

        # 3) Retrieve user info from Lark
        user_data = get_user_info(lark_access_token)
        open_id = user_data.get("open_id")
        if not open_id:
            raise AccessDenied("飞书返回的用户信息中没有 open_id")

        # 4) Find or bind user in Odoo by open_id
        user_id = self.sudo().search([("openid", "=", open_id)], limit=1)
        if not user_id:
            # Option A: raise an error if user must exist
            raise AccessDenied("用户绑定错误：open_id=%s" % open_id)

            # Option B (if you want to create a new user):
            # user_id = self.sudo().create({
            #     "login": user_data.get("email") or open_id,
            #     "openid": open_id,
            #     "name": user_data.get("name", "Lark User"),
            # })

        # 5) Optionally store or update user info
        user_id.oauth_access_token = lark_access_token
        # user_id.name = user_data.get("name") or user_id.name
        # user_id.email = user_data.get("email") or user_id.email
        # user_id.mobile = user_data.get("mobile") or user_id.mobile

        # 6) Return (db_name, user_login, token) so Odoo logs them in
        return (self.env.cr.dbname, user_id.login, lark_access_token)

    @api.model
    def auth_oauth(self, provider, params):
        """
        Override Odoo's default auth_oauth method to handle Lark specifically.
        """
        oauth_provider = self.env["auth.oauth.provider"].browse(int(provider))
        # If the provider's validation_endpoint is the Lark token URL, handle it
        if "open-apis/authen/v1/access_token" in oauth_provider.validation_endpoint:
            return self.auth_oauth_lark(oauth_provider, params)
        else:
            return super(ResUsers, self).auth_oauth(provider, params)
