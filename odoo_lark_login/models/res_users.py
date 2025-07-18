# -*- coding: utf-8 -*-

import logging
import requests
import simplejson
from werkzeug.urls import url_encode
from odoo import _, api, fields, models
from odoo.exceptions import AccessDenied, ValidationError


_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"

    openid = fields.Char(string="Openid")
    def unbind_from_lark(self):
        """Remove the Lark binding from the user."""
        self.ensure_one()
        self.write({'openid': False})
        _logger.info("User %s unbound from Lark", self.id)
        return {
            'type': 'ir.actions.client',
            'tag': 'reload',
        }

    def bind_to_lark(self):
        """
        This method is called from the user form (via a button) to initiate the Lark OAuth binding.
        It constructs the Lark authorization URL with required parameters and returns an action
        that redirects the user to Lark's OAuth endpoint.
        """
        self.ensure_one()
        app_id = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appid")
        bind_url = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.bind_url")
        base_url = self.env["ir.config_parameter"].sudo().get_param("web.base.url")

        state = {
            "u": self.id,
            "d": self.env.cr.dbname,
            "redirect_uri": base_url + "/",
        }

        params = {
            "response_type": "code",
            "app_id": app_id,
            "redirect_uri": bind_url,
            "scope": "lark_login",
            "state": simplejson.dumps(state),
        }
        lark_auth_endpoint = "https://open.larksuite.com/open-apis/authen/v1/index"
        oauth_url = "%s?%s" % (lark_auth_endpoint, url_encode(params))

        return {
            "type": "ir.actions.act_url",
            "target": "self",
            "url": oauth_url,
        }

    @api.model
    def auth_oauth(self, provider, params):
        """
        Override Odoo's default auth_oauth method to handle Lark-specific OAuth authentication.
        If the provider's validation_endpoint indicates a Lark provider, it calls the Lark-specific method.
        """
        oauth_provider = self.env["auth.oauth.provider"].browse(int(provider))
        if "open-apis/authen/v1/access_token" in oauth_provider.validation_endpoint:
            return self.auth_oauth_lark(oauth_provider, params)
        else:
            return super(ResUsers, self).auth_oauth(provider, params)

    @api.model
    def auth_oauth_lark(self, provider, params):
        """
        Handles Lark OAuth:
          1. Exchanges the authorization code for an access token.
          2. Retrieves user info from Lark.
          3. Finds (or binds) an Odoo user using the returned open_id.
        """
        def get_access_token(token_url, app_id, app_secret, code):
            headers = {"Content-Type": "application/json"}
            payload = {
                "grant_type": "authorization_code",
                "code": code,
                "app_id": app_id,
                "app_secret": app_secret,
            }
            response = requests.post(token_url, json=payload, headers=headers)
            token_res = response.json()
            if token_res.get("code") == 0:
                data = token_res.get("data", {})
                return data.get("access_token"), data.get("expires_in")
            else:
                raise AccessDenied(
                    "飞书获取access_token错误：code=%s, msg=%s"
                    % (token_res.get("code"), token_res.get("msg"))
                )

        def get_user_info(access_token):
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            }
            user_info_url = "https://open.larksuite.com/open-apis/authen/v1/user_info"
            response = requests.get(user_info_url, headers=headers)
            user_res = response.json()
            if user_res.get("code") == 0:
                return user_res.get("data", {})
            else:
                raise AccessDenied(
                    "飞书获取用户信息错误：code=%s, msg=%s"
                    % (user_res.get("code"), user_res.get("msg"))
                )

        def get_user_email(access_token, open_id):
            """
            Retrieve detailed user information (including email) from Lark's contact API.
            Ensure that the OAuth scope includes permission to access contact information.
            """
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            }
            url = "https://open.larksuite.com/open-apis/contact/v3/users?user_id_type=open_id&user_id={}".format(
                open_id)
            response = requests.get(url, headers=headers)

            email_res = response.json()
            if email_res.get("code") == 0:
                data = email_res.get("data", {})
                return data.get("email")
            else:
                return None

        code = params.get("access_token") or params.get("code")
        if not code:
            raise AccessDenied("飞书扫码错误：没有 code！")

        app_id = provider.client_id
        app_secret = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appsecret")
        token_url = provider.validation_endpoint

        lark_access_token, expires_in = get_access_token(token_url, app_id, app_secret, code)

        user_data = get_user_info(lark_access_token)
        open_id = user_data.get("open_id")
        if not open_id:
            raise AccessDenied("飞书返回的用户信息中没有 open_id")

        email = user_data.get("email")
        if not email:
            email = get_user_email(lark_access_token, open_id)

        if not email:
            raise AccessDenied("无法从飞书获取用户的邮箱信息")

        user = self.sudo().search([("openid", "=", open_id)], limit=1)

        if not user:
            email = user_data.get("email")
            if email:
                user = self.sudo().search([("login", "=", email)], limit=1)
            if not user:
                user = self.sudo().create({
                    'name': user_data.get("name", "Lark User"),
                    'login': email or f"lark_{open_id}@alitec.com",
                    'openid': open_id,
                    'groups_id': [(6, 0, [self.env.ref('base.group_portal').id])],
                })

        if not user:
            raise AccessDenied("用户绑定错误：open_id=%s" % open_id)

        user.write({
            "openid": open_id,
            "oauth_access_token": lark_access_token,
        })

        _logger.info("Successfully bound/updated user %s to open_id %s", user.id, open_id)

        return self.env.cr.dbname, user.login, lark_access_token