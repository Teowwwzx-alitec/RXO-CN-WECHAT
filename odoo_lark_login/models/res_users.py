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
            try:
                response = requests.post(token_url, json=payload, headers=headers, timeout=10)
                response.raise_for_status() # Check for HTTP errors
                token_res = response.json()
                # >>> Log Raw Token Response <<<
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
                # >>> Log Raw User Info Response <<<
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

            try:
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                email_res = response.json()

                # >>> Log Raw Contact API Response <<<
                _logger.info(f"Lark Contact API (/contact/v3/users) Raw Response: {simplejson.dumps(email_res)}")

                if email_res.get("code") == 0:
                    user_contact_data = email_res.get("data", {}).get("user", {})
                    if not user_contact_data:
                        _logger.warning(f"Contact API: Response 'data' field missing 'user' sub-key for open_id {open_id[:6]}. Will try getting email from 'data' directly.")
                        contact_data = email_res.get("data", {})
                        business_email = contact_data.get("enterprise_email")
                        standard_email = contact_data.get("email")
                    else:
                        business_email = user_contact_data.get("enterprise_email")
                        standard_email = user_contact_data.get("email")

                    # Log and return based on your previous preference (business > standard)
                    _logger.info(f"Contact API: Found 'enterprise_email': {business_email}")
                    _logger.info(f"Contact API: Found standard 'email'   : {standard_email}")

                    if business_email:
                        _logger.info("Contact API: Returning 'enterprise_email'.")
                        return business_email
                    elif standard_email:
                        _logger.info("Contact API: Returning standard 'email' as fallback.")
                        return standard_email
                    else:
                        _logger.warning(f"Contact API: Neither enterprise nor standard email found for open_id {open_id[:6]}.")
                        return None
                else:
                    _logger.error("Contact API: Request failed. Code: %s, Msg: %s", email_res.get("code"), email_res.get("msg"))
                    return None

            except requests.exceptions.RequestException as e:
                _logger.error(f"Contact API: Network error for open_id {open_id[:6]}: {e}", exc_info=True)
                return None

            except Exception as e:
                _logger.exception(f"Contact API: Unexpected error for open_id {open_id[:6]}.")
                return None

        code = params.get("access_token") or params.get("code")
        if not code:
            _logger.error("Lark OAuth Error: Missing code parameter.")
            raise AccessDenied("飞书扫码错误：没有 code！")

        # Log the received code
        _logger.info("Received Lark code (first 10 chars): %s...", code[:10] if code else 'None')

        app_id = provider.client_id
        app_secret = self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appsecret")
        token_url = provider.validation_endpoint

        lark_access_token, expires_in = get_access_token(token_url, app_id, app_secret, code)
        if not lark_access_token: # Added check in case get_access_token somehow returns None despite error handling
            _logger.error("Failed to obtain Lark access token.")
            raise AccessDenied("无法获取Lark访问令牌")
        _logger.info("Obtained Lark access token (first 5 chars): %s...", lark_access_token[:5])

        user_data = get_user_info(lark_access_token)
        open_id = user_data.get("open_id")
        if not open_id:
            raise AccessDenied("飞书返回的用户信息中没有 open_id")

        email = user_data.get("enterprise_email")
        _logger.info(f"Attempting to use enterprise_email from basic info: {email}")
        if not email:
            _logger.info("Enterprise email not in basic info, calling Contact API helper...")
            email = get_user_email(lark_access_token, open_id) # Helper logs raw response inside

        _logger.info(f"Final email determined for processing: {email}")

        # Check if email was found
        if not email:
            _logger.error(f"Could not determine any usable email for open_id {open_id[:6]}.")
            raise AccessDenied("无法从飞书获取用户的邮箱信息")

        # --- User Lookup/Creation (Using your existing logic, including the flaw) ---
        _logger.info(f"Searching for existing user by openid: {open_id[:6]}...")
        user = self.sudo().search([("openid", "=", open_id)], limit=1)

        if not user:
            _logger.info("User not found by openid.")
            email_from_basic_info = user_data.get("email")
            _logger.warning(
                f"FLAW WARNING: Now using standard 'email' from basic info ('{email_from_basic_info}') for search/create, NOT necessarily the prioritized email ('{email}').")

            if email_from_basic_info:
                _logger.info(f"Searching user by login = '{email_from_basic_info}'...")
                user = self.sudo().search([("login", "=", email_from_basic_info)], limit=1)

            if not user:
                login_value = email_from_basic_info or f"lark_{open_id}@alitec.asia"
                _logger.info(f"User not found by login. Creating new user with login='{login_value}'...")
                try:
                    user = self.sudo().create({
                        'name': user_data.get("name", f"Lark User {open_id[:6]}"),
                        'login': login_value,
                        'email': login_value,
                        'openid': open_id,
                        'groups_id': [(6, 0, [self.env.ref('base.group_portal').id])],
                        # Add standard OAuth fields
                        'oauth_provider_id': provider.id,
                        'oauth_uid': open_id,
                        'oauth_access_token': lark_access_token,
                        'active': True,
                    })
                    _logger.info(f"Created new user ID {user.id} with login {login_value}")
                except Exception as e_create:
                    _logger.exception(f"Failed to create user with login {login_value}")
                    raise AccessDenied(f"Failed to create Odoo user account: {e_create}")
            else:
                _logger.info(
                    f"Found user ID {user.id} by login '{email_from_basic_info}'. Linking openid {open_id[:6]}.")
                user.write({"openid": open_id})
        else:
            _logger.info(f"Found user ID {user.id} by openid {open_id[:6]}.")


        if not user:  # Final check
            _logger.error(f"User record is unexpectedly missing after processing for open_id {open_id[:6]}")
            raise AccessDenied("用户绑定错误：open_id=%s" % open_id)

        _logger.info("Successfully processed authentication for user %s (ID: %s) linked to open_id %s", user.login,
                     user.id, open_id)

        return self.env.cr.dbname, user.login, lark_access_token