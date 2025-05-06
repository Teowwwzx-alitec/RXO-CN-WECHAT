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
        if "open.larksuite.com/open-apis/authen/v1" in oauth_provider.validation_endpoint:
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
            try:
                response = requests.post(token_url, json=payload, headers=headers, timeout=10)
                response.raise_for_status()
                token_res = response.json()

                _logger.info(f"Lark Token Endpoint Raw Response: {simplejson.dumps(token_res)}") # Use simplejson for consistency
                if token_res.get("code") == 0:
                    data = token_res.get("data", {})
                    return data.get("access_token"), data.get("expires_in")
                else:
                    _logger.error("Lark get_access_token failed. Code: %s, Msg: %s", token_res.get("code"), token_res.get("msg"))
                    raise AccessDenied("飞书获取access_token错误：code=%s, msg=%s" % (token_res.get("code"), token_res.get("msg")))
            except requests.exceptions.RequestException as e:
                _logger.error(f"Network error calling Lark Token Endpoint: {e}", exc_info=True)
                raise AccessDenied(f"Network error getting Lark token: {e}")
            except Exception as e:
                _logger.exception(f"Error processing Lark Token response.")
                raise AccessDenied(f"Error processing Lark token response: {e}")

        def get_user_info(access_token):
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {access_token}",
            }
            user_info_url = "https://open.larksuite.com/open-apis/authen/v1/user_info"

            try:
                response = requests.get(user_info_url, headers=headers, timeout=10)
                response.raise_for_status()
                user_res = response.json()

                _logger.info(f"Lark User Info (/authen/v1/user_info) Raw Response: {simplejson.dumps(user_res)}")
                if user_res.get("code") == 0:
                    return user_res.get("data", {})
                else:
                    _logger.error("Lark get_user_info failed. Code: %s, Msg: %s", user_res.get("code"), user_res.get("msg"))
                    raise AccessDenied("飞书获取用户信息错误：code=%s, msg=%s" % (user_res.get("code"), user_res.get("msg")))
            except requests.exceptions.RequestException as e:
                 _logger.error(f"Network error calling Lark User Info Endpoint: {e}", exc_info=True)
                 raise AccessDenied(f"Network error getting Lark user info: {e}")
            except Exception as e:
                 _logger.exception(f"Error processing Lark User Info response.")
                 raise AccessDenied(f"Error processing Lark user info response: {e}")


        code = params.get("access_token") or params.get("code")
        if not code:
            _logger.error("Lark OAuth Error: Missing code parameter.")
            raise AccessDenied("飞书扫码错误：没有 code！")

        # Log the received code
        _logger.info("Received Lark code (first 10 chars): %s...", code[:10] if code else 'None')

        app_id = provider.client_id
        app_secret = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appsecret")
        token_url = "https://open.larksuite.com/open-apis/authen/v1/access_token"

        lark_access_token, expires_in = get_access_token(token_url, app_id, app_secret, code)

        if not lark_access_token:
            _logger.error("Failed to obtain Lark access token.")
            raise AccessDenied("无法获取Lark访问令牌")
        _logger.info("Obtained Lark access token (first 5 chars): %s...", lark_access_token[:5])

        user_data = get_user_info(lark_access_token)
        open_id = user_data.get("open_id")
        if not open_id:
            raise AccessDenied("飞书返回的用户信息中没有 open_id")

        email_to_use = user_data.get("email")
        if not email_to_use:
            email_to_use = user_data.get("enterprise_email")

        if not email_to_use:
            _logger.error(f"Could not determine any usable email for open_id {open_id[:6]} after calling Contact API.")
            raise AccessDenied(_("Could not retrieve a usable email address from Lark."))

        _logger.info(f"Searching for existing user by openid: {open_id[:6]}...")
        user = self.sudo().search([
            '|',
            ('openid', '=', open_id),
            ('oauth_uid', '=', open_id),
        ], limit=1)

        if not user:
            _logger.info(f"User not found by openid {open_id[:6]}. Searching by login/email: {email_to_use}...")
            if email_to_use:
                user = self.sudo().search([("login", "=", email_to_use)], limit=1)

            if not user:
                _logger.info(f"User not found by login '{email_to_use}'. Creating new user...")
                try:
                    user = self.sudo().create({
                        'name': user_data.get("name", f"Lark User {open_id[:6]}"),
                        'login': email_to_use,
                        'openid': open_id,
                        'groups_id': [(6, 0, [self.env.ref('base.group_portal').id])],
                        'active': True,
                        'oauth_provider_id': provider.id,
                        'oauth_uid': open_id,
                    })
                    _logger.info(f"Created new Odoo user ID {user.id} with login '{email_to_use}' linked to open_id {open_id[:6]}.")
                except Exception as e_create:
                    _logger.exception(f"Failed to create user with login '{email_to_use}'.")
                    raise AccessDenied(_("Failed to create Odoo user account: %s") % e_create)
        else:
            try:
                user.write({
                    "openid": open_id,
                    "oauth_access_token": lark_access_token,
                })
                _logger.info("Final write executed for user %s, setting openid and oauth_access_token.", user.id)
                _logger.info("Final write executed for ", lark_access_token)
            except Exception as e_final_write:
                _logger.exception(f"Failed during final write for user ID {user.id}.")
                raise AccessDenied(_("Failed to finalize user update: %s") % e_final_write)

        if not user:
            _logger.error(f"User record is unexpectedly missing after processing for open_id {open_id[:6]}")
            raise AccessDenied("用户绑定错误：open_id=%s" % open_id)

        _logger.info("Successfully processed authentication for user %s (ID: %s) linked to open_id %s", user.login, user.id, open_id)

        return self.env.cr.dbname, user.login, lark_access_token