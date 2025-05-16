# -*- coding: utf-8 -*-

import logging
import requests
import simplejson
import werkzeug.utils

from odoo import http, _
from odoo.http import request
from werkzeug.urls import url_encode
from werkzeug.exceptions import BadRequest
from odoo.exceptions import AccessDenied, ValidationError
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as BaseOAuthLogin
from odoo.addons.auth_oauth.controllers.main import OAuthController as BaseController


_logger = logging.getLogger(__name__)


class OAuthLogin(BaseOAuthLogin):
    def list_providers(self):
        providers = super(OAuthLogin, self).list_providers()
        for provider in providers:
            if "open.larksuite.com" in provider["validation_endpoint"]:
                dbname = request.session.db

                if not http.db_filter([dbname]):
                    return BadRequest()

                state = {
                    "p": str(provider["id"]),
                    "d": dbname,
                    "redirect_uri": request.httprequest.url_root,
                }
                appid = (
                    request.env["ir.config_parameter"]
                    .sudo()
                    .get_param("odoo_lark_login.appid")
                )
                return_url = (
                    request.env["ir.config_parameter"]
                    .sudo()
                    .get_param("odoo_lark_login.return_url")
                )

                params = {
                    "response_type": "code",
                    "app_id": appid,
                    "redirect_uri": return_url,
                    "scope": provider["scope"],
                    "state": simplejson.dumps(state),
                }
                provider["auth_link"] = "%s?%s" % (
                    provider["auth_endpoint"],
                    url_encode(params),
                )
        return providers


class OAuthController(BaseController):
    # Core function
    @http.route("/lark/login", type="http", auth="none")
    def lark_login(self, **kw):
        try:
            state = simplejson.loads(kw.get("state", ""))
        except Exception as e:
            return BadRequest("Invalid state parameter")
        redirect_uri = state.get("redirect_uri", request.httprequest.url_root)

        code = kw.get("code", "")
        if not code:
            return BadRequest("Missing code parameter")

        # Add a unique session identifier to support multiple browser logins
        # This doesn't affect the code parameter used for authentication
        import time
        import random
        import hashlib
        session_id = hashlib.md5(f"{time.time()}{random.random()}".encode()).hexdigest()[:8]
        
        # Important: Pass the code as access_token for authentication
        # Add our session identifier to the state for tracking
        state_data = simplejson.loads(kw.get("state", "{}"))
        state_data["session_id"] = session_id
        
        params = {
            "expires_in": 7200,
            "access_token": code,  # Pass code as access_token parameter
            "state": simplejson.dumps(state_data),
        }
        
        # Redirect to the standard Odoo OAuth signin
        return werkzeug.utils.redirect(
            redirect_uri + "auth_oauth/signin?%s" % url_encode(params)
        )

    # Bind function
    @http.route("/lark/bind", type="http", auth="none")
    def bind_to_lark(self, **kw):
        try:
            state = simplejson.loads(kw.get("state", ""))
        except Exception as e:
            return BadRequest("Invalid state parameter")
        redirect_uri = state.get("redirect_uri", request.httprequest.url_root)

        code = kw.get("code", "")
        if not code:
            return BadRequest("Missing code parameter")

        params = {
            "expires_in": 7200,
            "code": code,
            "scope": "lark_login",
            "token_type": "Bearer",
            "state": simplejson.dumps(state),
        }
        return werkzeug.utils.redirect(
            redirect_uri + "lark/bind/write?%s" % url_encode(params)
        )

    # Bind function
    @http.route("/lark/bind/write", type="http", auth="none")
    def bind_to_lark_write(self, **kw):

        code = kw.get("code")
        raw_state = kw.get("state")
        if not code or not raw_state:
            return BadRequest("Missing code or state parameter")

        try:
            state = simplejson.loads(raw_state)
        except Exception as e:
            return BadRequest("Invalid state parameter")

        request.session.db = state.get("d")

        user_id = state.get("u")
        if not user_id:
            return BadRequest("Missing user information in state")

        user = request.env["res.users"].sudo().browse(int(user_id))
        if not user:
            raise AccessDenied("系统中没有查到用户ID：id=%s" % user_id)

        appid = (
            request.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appid")
        )
        secret = (
            request.env["ir.config_parameter"]
            .sudo()
            .get_param("odoo_lark_login.appsecret")
        )
        token_url = "https://open.larksuite.com/open-apis/authen/v1/access_token"

        headers = {"Content-Type": "application/json"}
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "app_id": appid,
            "app_secret": secret,
        }
        response = requests.post(token_url, json=payload, headers=headers)

        try:
            dict_data = response.json()
        except Exception as ex:
            raise AccessDenied("Lark token endpoint returned invalid JSON")

        if dict_data.get("code") != 0:
            raise AccessDenied(
                "Lark获取access_token错误：code=%s, msg=%s"
                % (dict_data.get("code"), dict_data.get("msg"))
            )

        token_data = dict_data.get("data", {})
        open_id = token_data.get("open_id")
        if not open_id:
            raise AccessDenied("No open_id returned from Lark")

        user.sudo().write({"openid": open_id})
        # _logger.info("Successfully bound user %s to open_id %s", user.id, open_id)

        return werkzeug.utils.redirect("/web")

    @http.route("/lark/go", type="http", auth="none", sitemap=False)
    def lark_start_sso(self, **kwargs):
        """
        Initiates the Lark SSO flow immediately by reading the configured
        Lark OAuth provider settings and redirecting the user to Lark.
        """
        # _logger.info("Initiating Lark SSO flow via /lark/go...")
        try:
            # 1. Determine Database
            dbname = request.session.db or http.db_list()[0]
            if not http.db_filter([dbname]):
                return request.redirect("/web/login?lark_error=db_invalid")

            # 2. Get Expected Client ID from System Parameters
            expected_client_id = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("odoo_lark_login.appid")
            )
            if not expected_client_id:
                _logger.error(
                    "Lark App ID (Client ID) not configured in system parameters (odoo_lark_login.appid)."
                )
                return request.redirect("/web/login?lark_error=appid_config")

            # 3. Find the Enabled Lark Provider by Client ID
            Provider = request.env["auth.oauth.provider"].sudo()
            lark_provider = Provider.search(
                [
                    ("client_id", "=", expected_client_id),
                    ("enabled", "=", True),  # Make sure it's the active one
                ],
                limit=1,
            )

            if not lark_provider:
                _logger.error(
                    _(
                        "Enabled Lark OAuth provider with Client ID '%s' not found. Please configure it under Settings > Users & Companies > OAuth Providers."
                    )
                    % expected_client_id
                )
                # Use translated message for user
                return request.redirect(
                    f'/web/login?error={_("Lark login is not configured correctly.")}'
                )

            # --- Now use the dynamically found lark_provider record ---

            # 4. Prepare State
            return_url = request.httprequest.url_root
            state_dict = {"d": dbname, "p": lark_provider.id}
            state = simplejson.dumps(state_dict)

            # 5. Get Params from the Found Provider Record
            client_id = lark_provider.client_id  # Should match expected_client_id
            auth_endpoint = lark_provider.auth_endpoint
            scope = (
                lark_provider.scope
            )  # Read the scope directly from the provider config

            # Basic check for essential provider fields
            if not all([auth_endpoint, scope]):
                _logger.error(
                    "Lark OAuth provider (ID: %s) is missing configuration (Authorization URL or Scope).",
                    lark_provider.id,
                )
                return request.redirect(
                    f'/web/login?error={_("Lark login configuration is incomplete.")}'
                )

            # **Important Scope Check (Add this log)**
            if "lark_login" in scope and not ("authen:user.info" in scope):
                _logger.warning(
                    "Lark OAuth provider (ID: %s) scope ('%s') might be insufficient. Standard scopes like 'authen:user.info' are usually required.",
                    lark_provider.id,
                    scope,
                )

            # 6. Get Odoo Callback URL from System Parameter
            redirect_uri = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("odoo_lark_login.return_url")
            )
            if not redirect_uri:
                _logger.error(
                    "Lark return URL (odoo_lark_login.return_url) not configured in parameters."
                )
                return request.redirect(
                    f'/web/login?error={_("Lark login callback URL is not configured.")}'
                )

            # 7. Construct Lark Auth URL
            params = {
                "response_type": "code",
                "app_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,  # Use scope defined in the provider settings
                "state": state,
            }
            lark_auth_url = f"{auth_endpoint}?{url_encode(params)}"
            # _logger.info("Redirecting user to Lark via /lark/go...") # Removed URL from log for slight security

            # 8. Redirect User
            return werkzeug.utils.redirect(lark_auth_url, 302)

        except Exception as e:
            _logger.exception("Error initiating Lark SSO flow via /lark/go.")
            return request.redirect(
                f'/web/login?error={_("An unexpected error occurred during login.")}'
            )
