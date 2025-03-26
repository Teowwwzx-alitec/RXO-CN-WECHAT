# -*- coding: utf-8 -*-

import base64
import logging
from odoo.http import request
import hashlib
import json

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

    # 微信Token验证专用接口（用于公众号后台验证）
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
            return echostr  # 必须返回echostr字符串
        else:
            _logger.error(f"❌ Token验证失败 | 收到签名: {signature} | 计算签名: {hash_str}")
            return "Verification Failed"

    # 核心逻辑：处理微信授权回调
    @http.route('/form', type='http', auth='public', website=True, csrf=False)
    def handle_wechat_auth(self, **kwargs):
        # 注：此接口同时处理微信Token验证和用户授权回调
        # ----------------------------------------------------
        # 调试模式开关（正式环境设为False）
        DEBUG_MODE = True  # 本地测试时可临时开启

        # Step 1: 检查是否是微信服务器验证请求
        if 'echostr' in kwargs:
            return self.verify_wechat_token(**kwargs)

        # Step 2: 真实用户授权流程（携带code）
        code = kwargs.get('code')
        if not code:
            return self._error_response("请从微信公众号菜单访问本页面")

        # 调试模式下跳过微信API调用（直接模拟用户数据）
        if DEBUG_MODE and code == "TEST_CODE":
            debug_user_data = {
                "openid": "test_openid_123",
                "nickname": "测试用户",
                "headimgurl": "https://example.com/avatar.jpg"
            }
            http.request.session['wechat_user'] = debug_user_data
            return self._redirect_to_form(kwargs.get('token'), kwargs.get('lang'))

        # 正式逻辑：调用微信API获取用户信息
        try:
            # 参数配置
            APPID = 'wx295ee81aa896f0a7'
            SECRET = '0790aca54793c477c4e13c50b3ac6dcc'

            # 获取access_token
            token_url = f"https://api.weixin.qq.com/sns/oauth2/access_token?appid={APPID}&secret={SECRET}&code={code}&grant_type=authorization_code"
            token_resp = requests.get(token_url, timeout=10)
            token_data = token_resp.json()
            if 'errcode' in token_data:
                _logger.error(f"🚨 获取Token失败: {token_data}")
                return self._error_response("微信授权失败（错误代码：%s）" % token_data.get('errcode'))

            # 获取用户信息
            user_info_url = f"https://api.weixin.qq.com/sns/userinfo?access_token={token_data['access_token']}&openid={token_data['openid']}&lang=zh_CN"
            user_resp = requests.get(user_info_url, timeout=5)
            user_data = user_resp.json()
            if 'errcode' in user_data:
                return self._error_response("无法获取用户信息")

            # 存储用户数据到session
            http.request.session['wechat_user'] = {
                'openid': user_data.get('openid'),
                'nickname': user_data.get('nickname'),
                'avatar': user_data.get('headimgurl')
            }

            # 跳转到目标页面
            return self._redirect_to_form(kwargs.get('token'), kwargs.get('lang', 'zh_CN'))

        except Exception as e:
            _logger.error(f"⚠️ 系统异常: {str(e)}")
            return self._error_response("服务器出现错误，请联系管理员")

    def _redirect_to_form(self, token, lang):
        """ 跳转到表单页 """
        base_url = f"/forms?token={token}&lang={lang}"
        return http.request.redirect(base_url)

    def _error_response(self, message):
        """ 统一错误页面响应 """
        return http.request.render('wechat_login.error_template', {
            'error_message': message
        })

    # 修改后的display_form方法
    @http.route('/forms', type='http', auth='public', website=True)
    def display_form(self, **kwargs):
        user_data = http.request.session.get('wechat_user', {})

        # 记录用户数据到日志
        _logger.info("✅ 用户数据获取成功: %s", user_data)

        # 跳转到Odoo表单页，携带微信参数
        return http.request.redirect(
            f"/forms?openid={user_data['openid']}&nickname={user_data['nickname']}&token=xxx&lang=zh_CN"
        )

class FormSubmissionController(http.Controller):

    @http.route('/forms/submit', type='http', auth='public', website=True, csrf=False)
    def handle_form_submission(self, **post_data):
        # 获取表单数据
        name = post_data.get('name')
        phone = post_data.get('phone')
        openid = post_data.get('wechat_openid')
        # nickname = post_data.get('wechat_nickname')

        # 创建Odoo用户
        try:
            user = http.request.env['res.users'].sudo().create({
                'name': name,
                'login': phone,  # 使用手机号作为登录名
                'phone': phone,
                'openid': openid,  # 需要自定义字段存储OpenID
                # 'wechat_nickname': nickname,
            })
            return "✅ 注册成功！用户ID: %s" % user.id
        except UserError as e:
            return f"❌ 错误: {str(e)}"

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
