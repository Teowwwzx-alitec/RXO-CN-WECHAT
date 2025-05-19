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
        self.write({"openid": False})
        # _logger.info("User %s unbound from Lark", self.id)
        return {
            "type": "ir.actions.client",
            "tag": "reload",
        }

    def bind_to_lark(self):
        """
        This method is called from the user form (via a button) to initiate the Lark OAuth binding.
        It constructs the Lark authorization URL with required parameters and returns an action
        that redirects the user to Lark's OAuth endpoint.
        """
        self.ensure_one()
        app_id = (
            self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appid")
        )
        bind_url = (
            self.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.bind_url")
        )
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
        if (
            "open.larksuite.com/open-apis/authen/v1"
            in oauth_provider.validation_endpoint
        ):
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
                response = requests.post(
                    token_url, json=payload, headers=headers, timeout=10
                )
                response.raise_for_status()
                token_res = response.json()

                # _logger.info(f"Lark Token Endpoint Raw Response: {simplejson.dumps(token_res)}") # Use simplejson for consistency
                if token_res.get("code") == 0:
                    data = token_res.get("data", {})
                    return data.get("access_token"), data.get("expires_in")
                else:
                    _logger.error(
                        "Lark get_access_token failed. Code: %s, Msg: %s",
                        token_res.get("code"),
                        token_res.get("msg"),
                    )
                    raise AccessDenied(
                        "飞书获取access_token错误：code=%s, msg=%s"
                        % (token_res.get("code"), token_res.get("msg"))
                    )
            except requests.exceptions.RequestException as e:
                _logger.error(
                    f"Network error calling Lark Token Endpoint: {e}", exc_info=True
                )
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

                # _logger.info(f"Lark User Info (/authen/v1/user_info) Raw Response: {simplejson.dumps(user_res)}")
                if user_res.get("code") == 0:
                    return user_res.get("data", {})
                else:
                    _logger.error(
                        "Lark get_user_info failed. Code: %s, Msg: %s",
                        user_res.get("code"),
                        user_res.get("msg"),
                    )
                    raise AccessDenied(
                        "飞书获取用户信息错误：code=%s, msg=%s"
                        % (user_res.get("code"), user_res.get("msg"))
                    )
            except requests.exceptions.RequestException as e:
                _logger.error(
                    f"Network error calling Lark User Info Endpoint: {e}", exc_info=True
                )
                raise AccessDenied(f"Network error getting Lark user info: {e}")
            except Exception as e:
                _logger.exception(f"Error processing Lark User Info response.")
                raise AccessDenied(f"Error processing Lark user info response: {e}")

        code = params.get("access_token") or params.get("code")
        if not code:
            _logger.error("Lark OAuth Error: Missing code parameter.")
            raise AccessDenied("飞书扫码错误：没有 code！")

        # Log the received code
        # _logger.info("Received Lark code (first 10 chars): %s...", code[:10] if code else 'None')

        app_id = provider.client_id
        app_secret = (
            self.env["ir.config_parameter"]
            .sudo()
            .get_param("odoo_lark_login.appsecret")
        )
        token_url = "https://open.larksuite.com/open-apis/authen/v1/access_token"

        # Get the new access token from Lark
        new_access_token, expires_in = get_access_token(token_url, app_id, app_secret, code)

        if not new_access_token:
            _logger.error("Failed to obtain Lark access token.")
            raise AccessDenied("无法获取Lark访问令牌")
        
        # Get user info from Lark to obtain the open_id
        user_data = get_user_info(new_access_token)
        open_id = user_data.get("open_id")
        if not open_id:
            raise AccessDenied("飞书返回的用户信息中没有 open_id")

        # Look for existing user with this open_id
        user = self.sudo().search([
            "|",
            ("openid", "=", open_id),
            ("oauth_uid", "=", open_id),
        ], limit=1)

        # ------ TOKEN MANAGEMENT STARTS HERE ------
        # Check if we already have a session for this user
        LarkSession = self.env["lark.user.session"].sudo()
        
        if user:
            # First, try to find an existing valid token for this user
            existing_session = LarkSession.search([
                ("user_id", "=", user.id), 
                ("active", "=", True),
                ("expire_date", ">", fields.Datetime.now())
            ], limit=1, order="create_date DESC")
            
            # If we found a valid token, use that instead of the new token
            if existing_session:
                # Update last used time
                existing_session.write({"last_used": fields.Datetime.now()})
                
                # Important: use the existing token for authentication
                # This is key to preventing session invalidation
                token_to_use = existing_session.token
                # _logger.info("Using existing token for authentication")
            else:
                # No valid token found, create a new session with the new token
                LarkSession.create({
                    "user_id": user.id,
                    "token": new_access_token,
                    "expires_in": expires_in
                })
                token_to_use = new_access_token
                # _logger.info("Created new token session")
        else:
            # For new users, always use the new token
            token_to_use = new_access_token
            # We'll create a session later after the user is created
        # ------ TOKEN MANAGEMENT ENDS HERE ------

        # Continue with email handling for user creation/lookup
        email_to_use = user_data.get("email")
        
        if not email_to_use:
            # _logger.error(f"Could not determine any usable email for open_id {open_id[:6]}")
            raise AccessDenied(_("Could not retrieve a usable email address from Lark."))

        # If user not found by open_id, search by email
        if not user:
            if email_to_use:
                user = self.sudo().search([("login", "=", email_to_use)], limit=1)

            # If still not found, create a new user
            if not user:
                try:
                    user = self.sudo().create(
                        {
                            "name": user_data.get("name", f"Lark User {open_id[:6]}"),
                            "login": email_to_use,
                            "openid": open_id,
                            "groups_id": [
                                (6, 0, [self.env.ref("base.group_portal").id])
                            ],
                            "active": True,
                            "oauth_provider_id": provider.id,
                            "oauth_uid": open_id,
                            "oauth_access_token": token_to_use,  # Use our managed token
                        }
                    )
                    
                    # For new users, create a session record
                    if token_to_use == new_access_token:  # If using the new token
                        LarkSession.create({
                            "user_id": user.id,
                            "token": new_access_token,
                            "expires_in": expires_in
                        })
                        
                except Exception as e_create:
                    _logger.exception(f"Failed to create user with login '{email_to_use}'.")
                    raise AccessDenied(_("Failed to create Odoo user account: %s") % e_create)
        
        # For existing users, update the open_id and token
        if user and user.id:
            try:
                user.write({
                    "openid": open_id,
                    "oauth_access_token": token_to_use,  # Use our managed token
                })
            except Exception as e_final_write:
                _logger.exception(f"Failed during final write for user ID {user.id}.")
                raise AccessDenied(_("Failed to finalize user update: %s") % e_final_write)

        if not user:
            _logger.error(f"User record is unexpectedly missing after processing for open_id {open_id[:6]}")
            raise AccessDenied("用户绑定错误：open_id=%s" % open_id)

        # Return the database, login and token for Odoo's session
        return self.env.cr.dbname, user.login, token_to_use
