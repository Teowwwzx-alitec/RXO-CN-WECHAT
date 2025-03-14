# -*- coding: utf-8 -*-

import base64
import logging
from odoo.http import request
import hashlib

import simplejson
import requests
import werkzeug.utils
from werkzeug.exceptions import BadRequest
from werkzeug.urls import url_encode

from odoo import http
from odoo.exceptions import AccessDenied, ValidationError
from odoo.addons.auth_oauth.controllers.main import OAuthController as BaseController
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as BaseOAuthLogin


_logger = logging.getLogger(__name__)


class OAuthLogin(BaseOAuthLogin):
    def list_providers(self):
        # _logger.debug(">>> [DEBUG] Entering list_providers for Lark")
        providers = super(OAuthLogin, self).list_providers()
        for provider in providers:
            if "open.larksuite.com" in provider["validation_endpoint"]:
                # _logger.debug(">>> [DEBUG] Found Lark provider: %s", provider)
                dbname = request.session.db
                # _logger.debug(">>> [DEBUG] Current session DB: %s", dbname)

                if not http.db_filter([dbname]):
                    # _logger.error(">>> [ERROR] DB Filter failed for %s", dbname)
                    return BadRequest()

                state = {
                    "p": str(provider["id"]),
                    "d": dbname,
                    "redirect_uri": request.httprequest.url_root,
                }
                appid = request.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appid")
                return_url = request.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.return_url")
                # _logger.debug(">>> [DEBUG] Lark AppID: %s | Return URL: %s", appid, return_url)

                params = {
                    "response_type": "code",
                    "app_id": appid,
                    "redirect_uri": return_url,
                    "scope": provider["scope"],
                    "state": simplejson.dumps(state),
                }
                provider["auth_link"] = "%s?%s" % (provider["auth_endpoint"], url_encode(params))
                # _logger.debug(">>> [DEBUG] Constructed Lark auth_link: %s", provider["auth_link"])
        return providers


class OAuthController(BaseController):
    @http.route("/lark/login", type="http", auth="none")
    def lark_login(self, **kw):
        # _logger.debug(">>> [DEBUG] lark_login with params: %s", kw)
        try:
            # state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
            state = simplejson.loads(kw.get("state", ""))
        except Exception as e:
            # _logger.error("State decoding error: %s", e)
            return BadRequest("Invalid state parameter")
        redirect_uri = state.get("redirect_uri", request.httprequest.url_root)

        # If the user denies authorization, there may be no code.
        code = kw.get("code", "")
        if not code:
            return BadRequest("Missing code parameter")

        # These parameters will be passed to the oauth_signin handler
        params = {
            "expires_in": 7200,
            "access_token": code,  # temporary placeholder; token exchange happens later
            "scope": "lark_login",
            "token_type": "Bearer",
            "state": simplejson.dumps(state),
        }
        return werkzeug.utils.redirect(
            redirect_uri + "auth_oauth/signin?%s" % url_encode(params)
        )

    # Route for Lark binding redirect
    @http.route("/lark/bind", type="http", auth="none")
    def bind_to_lark(self, **kw):
        # _logger.debug(">>> [DEBUG] bind_to_lark with params: %s", kw)
        try:
            # state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
            state = simplejson.loads(kw.get("state", ""))
        except Exception as e:
            # _logger.error("State decoding error: %s", e)
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

    @http.route("/lark/bind/write", type="http", auth="none")
    def bind_to_lark_write(self, **kw):
        # _logger.debug(">>> [DEBUG] bind_to_lark_write called with params: %s", kw)

        code = kw.get("code")
        raw_state = kw.get("state")
        if not code or not raw_state:
            return BadRequest("Missing code or state parameter")

        # Decode the state
        try:
            # state = simplejson.loads(base64.b64decode(raw_state).decode("utf-8"))
            state = simplejson.loads(raw_state)
        except Exception as e:
            # _logger.error("State decoding error: %s", e)
            return BadRequest("Invalid state parameter")

        # Switch to correct DB
        request.session.db = state.get("d")

        user_id = state.get("u")
        if not user_id:
            return BadRequest("Missing user information in state")

        # Make sure the user exists
        users = request.env["res.users"].sudo().browse(int(user_id))
        if not users:
            raise AccessDenied("系统中没有查到用户ID：id=%s" % user_id)

        # Exchange the code for an access token using POST + JSON
        # (If you still use GET with query params, you'll likely get an error)
        appid = request.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appid")
        secret = request.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appsecret")
        token_url = "https://open.larksuite.com/open-apis/authen/v1/access_token"

        headers = {"Content-Type": "application/json"}
        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "app_id": appid,
            "app_secret": secret,
        }
        response = requests.post(token_url, json=payload, headers=headers)
        # _logger.debug("Lark token response text: %s", response.text)

        try:
            dict_data = response.json()
        except Exception as ex:
            # _logger.error("Failed to parse JSON: %s", ex)
            raise AccessDenied("Lark token endpoint returned invalid JSON")

        if dict_data.get("code") != 0:
            raise AccessDenied(
                "Lark获取access_token错误：code=%s, msg=%s"
                % (dict_data.get("code"), dict_data.get("msg"))
            )

        # On success, 'data' should have an 'open_id'
        token_data = dict_data.get("data", {})
        open_id = token_data.get("open_id")
        if not open_id:
            raise AccessDenied("No open_id returned from Lark")

        # Bind the user
        users.sudo().write({"openid": open_id})
        _logger.info("Successfully bound user %s to open_id %s", users.id, open_id)

        return werkzeug.utils.redirect("/web")

