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
from odoo.addons.auth_oauth.controllers.main import OAuthController as Controller
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as Home

_logger = logging.getLogger(__name__)


class OAuthLogin(Home):
    def list_providers(self):
        _logger.debug(">>> [DEBUG] list_providers for Lark")
        providers = super(OAuthLogin, self).list_providers()
        for provider in providers:
            # Identify the Lark provider by its validation_endpoint (update as needed)
            if "open.larksuite.com" in provider["validation_endpoint"]:
                dbname = request.session.db
                if not http.db_filter([dbname]):
                    return BadRequest()
                # Store provider id, current database and redirect URL in state
                state = {
                    "p": str(provider["id"]),
                    "d": dbname,
                    "redirect_uri": request.httprequest.url_root,
                }
                # Retrieve Lark app credentials from configuration parameters
                APPID = (
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
                    "app_id": APPID,
                    "redirect_uri": return_url,
                    "scope": provider["scope"],
                    # base64-encode state and decode to string for URL transmission
                    "state": base64.b64encode(simplejson.dumps(state).encode("utf-8")).decode("utf-8"),
                }
                provider["auth_link"] = "%s?%s" % (
                    provider["auth_endpoint"],
                    url_encode(params),
                )
        return providers


class OAuthController(BaseController):
    # Lark does not require a server verification endpoint like WeChat.
    # Thus, we omit any "/lark" GET verification route.

    # Route for Lark OAuth login redirection
    @http.route("/lark/login", type="http", auth="none")
    def lark_login(self, **kw):
        _logger.debug(">>> [DEBUG] lark_login with params: %s", kw)
        try:
            state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
        except Exception as e:
            _logger.error("State decoding error: %s", e)
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
        _logger.debug(">>> [DEBUG] bind_to_lark with params: %s", kw)
        try:
            state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
        except Exception as e:
            _logger.error("State decoding error: %s", e)
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

    # Route for processing Lark binding
    @http.route("/lark/bind/write", type="http", auth="none")
    def bind_to_lark_write(self, **kw):
        _logger.debug(">>> [DEBUG] bind_to_lark_write called with params: %s", kw)

        def gettoken(code):
            _logger.debug(">>> [DEBUG] gettoken called with code: %s", code)
            appid = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("odoo_lark_login.appid")
            )
            secret = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("odoo_lark_login.appsecret")
            )
            # Lark access token URL per documentation
            url_token = (
                "https://open.larksuite.com/open-apis/authen/v1/access_token?app_id=%s&app_secret=%s&code=%s"
                % (appid, secret, code)
            )
            headers = {"Content-Type": "application/json"}
            response = requests.get(url_token, headers=headers)
            dict_data = response.json()
            _logger.debug(">>> [DEBUG] Lark token response: %s", dict_data)
            if dict_data.get("code") == 0:
                # On success, return the token data.
                return dict_data["data"]
            else:
                raise AccessDenied(
                    "Lark获取access_token错误：code=%s, msg=%s"
                    % (dict_data.get("code"), dict_data.get("msg"))
                )

        code = kw.get("code", "")
        state = kw.get("state", "")
        if not code or not state:
            return BadRequest("Missing code or state parameter")
        try:
            state = simplejson.loads(state)
        except Exception as e:
            _logger.error("State decoding error: %s", e)
            return BadRequest("Invalid state parameter")

        # Set the session database based on state; assume state includes a user id under key "u"
        request.session.db = state.get("d")
        user_id = state.get("u")
        if not user_id:
            return BadRequest("Missing user information in state")
        users = request.env["res.users"].sudo().browse(user_id)
        if users:
            token_data = gettoken(code)
            # Assuming Lark returns a unique identifier under key 'open_id'
            users.sudo().write({"openid": token_data.get("open_id")})
            return werkzeug.utils.redirect("/web")
        else:
            raise AccessDenied("系统中没有查到用户ID：id=%s" % user_id)
