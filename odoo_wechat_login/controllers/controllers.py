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
    print(">>> [DEBUG] OAuthLogin", flush=True)

    def list_providers(self):
        print(">>> [DEBUG] list_providers")

        # 获取所有的OAuth服务商
        providers = super(OAuthLogin, self).list_providers()
        for provider in providers:
            if "api.weixin.qq.com/sns/oauth2" in provider["validation_endpoint"]:
                # 封装发起请求时的参数、构造微信请求参数
                dbname = request.session.db
                if not http.db_filter([dbname]):
                    return BadRequest()
                # 我们将服务商id、请求的数据库、url地址存在state中，后面函数会用到这些值
                state = {
                    "p": str(provider["id"]),
                    "d": dbname,
                    "redirect_uri": request.httprequest.url_root,
                }
                # provider['auth_endpoint']获取的就是身份验证网址
                # 服务商的相关字段信息可以在数据库结构中搜索模型auth就可以找到了
                # 你的微信APPID
                APPID = (
                    request.env["ir.config_parameter"]
                    .sudo()
                    .get_param("odoo_wechat_login.appid")
                )
                return_url = (
                    request.env["ir.config_parameter"]
                    .sudo()
                    .get_param("odoo_wechat_login.return_url")
                )

                params = dict(
                    response_type="code",
                    appid=APPID,
                    # 因为一个应用只能配置一个域名下的回调地址，所以这块设置了一个静态值，由此静态值分发请求
                    redirect_uri=return_url,
                    scope=provider["scope"],
                    # 使用base64加密的形式进行传输，普通的json会被微信处理成乱码
                    state=base64.b64encode(simplejson.dumps(state).encode("utf-8")),
                )
                # 最终的微信登入请求链接
                provider["auth_link"] = "%s?%s" % (
                    provider["auth_endpoint"],
                    url_encode(params),
                )
        return providers


class OAuthController(Controller):
    # New route for WeChat server verification
    @http.route("/wechat", type="http", auth="none", methods=["GET", "POST"])
    def wechat_verify(self, **kw):
        """Handles WeChat server verification and message handling"""
        if request.httprequest.method == "GET":
            token = request.env["ir.config_parameter"].sudo().get_param("odoo_wechat_login.token")
            signature = kw.get("signature", "")
            timestamp = kw.get("timestamp", "")
            nonce = kw.get("nonce", "")
            echostr = kw.get("echostr", "")

            if self.check_signature(token, signature, timestamp, nonce):
                return echostr  # Verification successful
            else:
                return "Verification failed"

        return "Unsupported method", 405

    def check_signature(self, token, signature, timestamp, nonce):
        """Verify WeChat server signature"""
        tmpArr = [token, timestamp, nonce]
        tmpArr.sort()
        tmpStr = "".join(tmpArr).encode("utf-8")
        tmpStr = hashlib.sha1(tmpStr).hexdigest()
        return tmpStr == signature
    
    # 此路由只会被分发网址使用，进行数据处理后，转发至各个网址进行登录
    @http.route("/wechat/login", type="http", auth="none")
    def wechat_login(self, **kw):
        state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
        redirect_uri = state["redirect_uri"]
        # 以上两步未做判断，因为是自己加的参数，即使请求失败也不会出错

        # 若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
        code = kw.get("code", "")
        if not code:
            return BadRequest()

        # 拼接请求参数
        params = {
            "expires_in": 7200,
            "access_token": code,
            "scope": "snsapi_login",
            "token_type": "Bearer",
            "state": simplejson.dumps(state),
        }

        # 分发请求
        return werkzeug.utils.redirect(
            redirect_uri + "auth_oauth/signin?%s" % url_encode(params)
        )

    # 进行数据处理后，转发至各个网址进行绑定
    @http.route("/wechat/bind", type="http", auth="none")

    def bind_to_wechat(self, **kw):
        print(">>> [DEBUG] bind_to_wechat", flush=True)

        state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
        redirect_uri = state["redirect_uri"]
        # 以上两步未做判断，因为是自己加的参数，即使请求失败也不会出错

        # 若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
        code = kw.get("code", "")
        if not code:
            return BadRequest()

        # 拼接请求参数
        params = {
            "expires_in": 7200,
            "code": code,
            "scope": "snsapi_login",
            "token_type": "Bearer",
            "state": simplejson.dumps(state),
        }
        # 分发请求
        return werkzeug.utils.redirect(
            redirect_uri + "wechat/bind/write?%s" % url_encode(params)
        )

    # 进行数据处理绑定
    @http.route("/wechat/bind/write", type="http", auth="none")
    def bind_to_wechat_write(self, **kw):
        print(">>> [DEBUG] bind_to_wechat_write called with params:", kw, flush=True)

        def gettoken(code):
            print(">>> [DEBUG] gettoken called with code:", code, flush=True)

            appid = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("odoo_wechat_login.appid")
            )
            secret = (
                request.env["ir.config_parameter"]
                .sudo()
                .get_param("odoo_wechat_login.appsecret")
            )
            print(">>> [DEBUG] gettoken called with code:", code, flush=True)

            url_token = (
                "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code"
                % (appid, secret, code)
            )
            headers = {"Content-Type": "application/json"}
            response = requests.get(url_token, headers=headers)
            dict_data = response.json()
            errcode = dict_data.get("errcode", 0)
            if errcode == 0:
                return dict_data
            else:
                raise AccessDenied(
                    "微信获取access_token错误：err_code=%s, err_msg=%s"
                    % (dict_data["errcode"], dict_data["errmsg"])
                )

        # 若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
        code = kw.get("code", "")
        state = kw.get("state", "")
        if not code or not state:
            return BadRequest()
        state = simplejson.loads(state)
        request.session.db = state["d"]
        users = request.env["res.users"].sudo().browse(state["u"])
        if users:
            dict_data = gettoken(code)
            users.sudo().write({"openid": dict_data["openid"]})
            return werkzeug.utils.redirect("/web")
        else:
            raise AccessDenied("系统中没有查到用户ID：id=%s" % (state["u"]))
