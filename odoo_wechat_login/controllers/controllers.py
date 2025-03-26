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


class WechatAuthController(http.Controller):

    # ---------------------
    # 核心修改点：拆分Token验证和业务处理到不同路由
    # ---------------------

    # 微信Token验证专用接口（仅响应官方验证）
    @http.route('/wechat-verify', type='http', auth='public', methods=['GET'], csrf=False)
    def verify_wechat_token(self, **kwargs):
        signature = kwargs.get('signature', '')
        timestamp = kwargs.get('timestamp', '')
        nonce = kwargs.get('nonce', '')
        echostr = kwargs.get('echostr', '')
        token = "JIivg0Um8i0b6hGZ4bYQ3q"

        tmp_list = sorted([token, timestamp, nonce])
        tmp_str = ''.join(tmp_list).encode('utf-8')
        hash_str = hashlib.sha1(tmp_str).hexdigest()

        if hash_str == signature:
            _logger.info("✅ 微信Token验证成功")
            return echostr  # 关键：直接返回echostr
        else:
            _logger.error(f"❌ Token验证失败 | Received: {signature} | Calculated: {hash_str}")
            return "Verification Failed"

            # 集成授权的核心处理逻辑

    @http.route('/form', type='http', auth='public', website=True, csrf=False, methods=['GET'])
    def handle_wechat_auth(self, **kwargs):
        """ 处理微信OAuth回调及用户信息获取 """
        # Step 1: 微信服务器验证请求（GET请求不带code）
        if 'echostr' in kwargs:
            return self.verify_wechat_token(**kwargs)

        # Step 2: 用户携带code回调（微信OAuth流程）
        code = kwargs.get('code')
        if not code:
            return "⚠️ 请通过微信公众号菜单访问本页面"

        # 配置参数
        APPID = 'wx295ee81aa896f0a7'
        SECRET = '0790aca54793c477c4e13c50b3ac6dcc'

        # 步骤1：通过code获取access_token和openid
        token_url = f"https://api.weixin.qq.com/sns/oauth2/access_token?appid={APPID}&secret={SECRET}&code={code}&grant_type=authorization_code"
        try:
            token_resp = requests.get(token_url, timeout=10)
            token_data = token_resp.json()
            if 'errcode' in token_data:
                _logger.error(f"🚨 Token获取失败: {token_data}")
                return "微信授权失败（代码错误或已过期）"
        except Exception as e:
            _logger.error(f"⚠️ 微信API请求异常: {str(e)}")
            return "服务暂时不可用，请重试"

        # 步骤2：获取用户详细信息（需snsapi_userinfo）
        user_info_url = f"https://api.weixin.qq.com/sns/userinfo?access_token={token_data['access_token']}&openid={token_data['openid']}&lang=zh_CN"
        try:
            user_resp = requests.get(user_info_url, timeout=5)
            user_data = user_resp.json()
            if 'errcode' in user_data:
                _logger.error(f"🚨 用户信息获取失败: {user_data}")
                return "无法获取用户信息"
        except Exception as e:
            _logger.error(f"⚠️ 用户信息API异常: {str(e)}")
            return "数据加载失败"

        # 安全处理：将关键数据存入session（推荐）
        http.request.session['wechat_user'] = {
            'openid': user_data.get('openid'),
            'nickname': user_data.get('nickname'),
            'avatar': user_data.get('headimgurl'),
            # 其他需要保留的字段...
        }

        # 跳转到含参数的目标页（避免URL暴露敏感数据）
        return http.request.redirect(f"/forms?token={kwargs.get('token', '')}&lang={kwargs.get('lang', 'zh_CN')}")

    @http.route('/forms', type='http', auth='public', website=True)
    def display_form(self, **kwargs):
        """ 展示实际表单页 """
        user_data = http.request.session.get('wechat_user', {})
        return http.request.render('your_module.template_name', {
            'openid': user_data.get('openid', ''),
            'nickname': user_data.get('nickname', ''),
            # 其他需要传递给模板的字段
        })

# class OAuthLogin(Home):
#     print(">>> [DEBUG] OAuthLogin", flush=True)
#
#     def list_providers(self):
#         print(">>> [DEBUG] list_providers")
#
#         # 获取所有的OAuth服务商
#         providers = super(OAuthLogin, self).list_providers()
#         for provider in providers:
#             if "api.weixin.qq.com/sns/oauth2" in provider["validation_endpoint"]:
#                 # 封装发起请求时的参数、构造微信请求参数
#                 dbname = request.session.db
#                 if not http.db_filter([dbname]):
#                     return BadRequest()
#                 # 我们将服务商id、请求的数据库、url地址存在state中，后面函数会用到这些值
#                 state = {
#                     "p": str(provider["id"]),
#                     "d": dbname,
#                     "redirect_uri": request.httprequest.url_root,
#                 }
#                 # provider['auth_endpoint']获取的就是身份验证网址
#                 # 服务商的相关字段信息可以在数据库结构中搜索模型auth就可以找到了
#                 # 你的微信APPID
#                 APPID = (
#                     request.env["ir.config_parameter"]
#                     .sudo()
#                     .get_param("odoo_wechat_login.appid")
#                 )
#                 return_url = (
#                     request.env["ir.config_parameter"]
#                     .sudo()
#                     .get_param("odoo_wechat_login.return_url")
#                 )
#
#                 params = dict(
#                     response_type="code",
#                     appid=APPID,
#                     # 因为一个应用只能配置一个域名下的回调地址，所以这块设置了一个静态值，由此静态值分发请求
#                     redirect_uri=return_url,
#                     scope=provider["scope"],
#                     # 使用base64加密的形式进行传输，普通的json会被微信处理成乱码
#                     state=base64.b64encode(simplejson.dumps(state).encode("utf-8")),
#                 )
#                 # 最终的微信登入请求链接
#                 provider["auth_link"] = "%s?%s" % (
#                     provider["auth_endpoint"],
#                     url_encode(params),
#                 )
#         return providers
#
#
# class OAuthController(Controller):
#     # New route for WeChat server verification
#     @http.route("/wechat", type="http", auth="none", methods=["GET", "POST"])
#     def wechat_verify(self, **kw):
#         """Handles WeChat server verification and message handling"""
#         if request.httprequest.method == "GET":
#             token = request.env["ir.config_parameter"].sudo().get_param("odoo_wechat_login.token")
#             signature = kw.get("signature", "")
#             timestamp = kw.get("timestamp", "")
#             nonce = kw.get("nonce", "")
#             echostr = kw.get("echostr", "")
#
#             if self.check_signature(token, signature, timestamp, nonce):
#                 return echostr  # Verification successful
#             else:
#                 return "Verification failed"
#
#         return "Unsupported method", 405
#
#     def check_signature(self, token, signature, timestamp, nonce):
#         """Verify WeChat server signature"""
#         tmpArr = [token, timestamp, nonce]
#         tmpArr.sort()
#         tmpStr = "".join(tmpArr).encode("utf-8")
#         tmpStr = hashlib.sha1(tmpStr).hexdigest()
#         return tmpStr == signature
#
#     # 此路由只会被分发网址使用，进行数据处理后，转发至各个网址进行登录
#     @http.route("/wechat/login", type="http", auth="none")
#     def wechat_login(self, **kw):
#         state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
#         redirect_uri = state["redirect_uri"]
#         # 以上两步未做判断，因为是自己加的参数，即使请求失败也不会出错
#
#         # 若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
#         code = kw.get("code", "")
#         if not code:
#             return BadRequest()
#
#         # 拼接请求参数
#         params = {
#             "expires_in": 7200,
#             "access_token": code,
#             "scope": "snsapi_login",
#             "token_type": "Bearer",
#             "state": simplejson.dumps(state),
#         }
#
#         # 分发请求
#         return werkzeug.utils.redirect(
#             redirect_uri + "auth_oauth/signin?%s" % url_encode(params)
#         )
#
#     # 进行数据处理后，转发至各个网址进行绑定
#     @http.route("/wechat/bind", type="http", auth="none")
#
#     def bind_to_wechat(self, **kw):
#         print(">>> [DEBUG] bind_to_wechat", flush=True)
#
#         state = simplejson.loads(base64.b64decode(kw.get("state")).decode())
#         redirect_uri = state["redirect_uri"]
#         # 以上两步未做判断，因为是自己加的参数，即使请求失败也不会出错
#
#         # 若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
#         code = kw.get("code", "")
#         if not code:
#             return BadRequest()
#
#         # 拼接请求参数
#         params = {
#             "expires_in": 7200,
#             "code": code,
#             "scope": "snsapi_login",
#             "token_type": "Bearer",
#             "state": simplejson.dumps(state),
#         }
#         # 分发请求
#         return werkzeug.utils.redirect(
#             redirect_uri + "wechat/bind/write?%s" % url_encode(params)
#         )
#
#     # 进行数据处理绑定
#     @http.route("/wechat/bind/write", type="http", auth="none")
#     def bind_to_wechat_write(self, **kw):
#         print(">>> [DEBUG] bind_to_wechat_write called with params:", kw, flush=True)
#
#         def gettoken(code):
#             print(">>> [DEBUG] gettoken called with code:", code, flush=True)
#
#             appid = (
#                 request.env["ir.config_parameter"]
#                 .sudo()
#                 .get_param("odoo_wechat_login.appid")
#             )
#             secret = (
#                 request.env["ir.config_parameter"]
#                 .sudo()
#                 .get_param("odoo_wechat_login.appsecret")
#             )
#             print(">>> [DEBUG] gettoken called with code:", code, flush=True)
#
#             url_token = (
#                 "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code"
#                 % (appid, secret, code)
#             )
#             headers = {"Content-Type": "application/json"}
#             response = requests.get(url_token, headers=headers)
#             dict_data = response.json()
#             errcode = dict_data.get("errcode", 0)
#             if errcode == 0:
#                 return dict_data
#             else:
#                 raise AccessDenied(
#                     "微信获取access_token错误：err_code=%s, err_msg=%s"
#                     % (dict_data["errcode"], dict_data["errmsg"])
#                 )
#
#         # 若用户禁止授权，则重定向后不会带上code参数，仅会带上state参数
#         code = kw.get("code", "")
#         state = kw.get("state", "")
#         if not code or not state:
#             return BadRequest()
#         state = simplejson.loads(state)
#         request.session.db = state["d"]
#         users = request.env["res.users"].sudo().browse(state["u"])
#         if users:
#             dict_data = gettoken(code)
#             users.sudo().write({"openid": dict_data["openid"]})
#             return werkzeug.utils.redirect("/web")
#         else:
#             raise AccessDenied("系统中没有查到用户ID：id=%s" % (state["u"]))
