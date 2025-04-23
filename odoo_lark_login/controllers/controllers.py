# -*- coding: utf-8 -*-

import logging
import requests
import simplejson
import werkzeug.utils

from odoo import http
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
                appid = request.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.appid")
                return_url = request.env["ir.config_parameter"].sudo().get_param("odoo_lark_login.return_url")

                params = {
                    "response_type": "code",
                    "app_id": appid,
                    "redirect_uri": return_url,
                    "scope": provider["scope"],
                    "state": simplejson.dumps(state),
                }
                provider["auth_link"] = "%s?%s" % (provider["auth_endpoint"], url_encode(params))
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

        params = {
            "expires_in": 7200,
            "access_token": code,
            "scope": "lark_login",
            "token_type": "Bearer",
            "state": simplejson.dumps(state),
        }
        # Redirect to the function in res_users.py
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