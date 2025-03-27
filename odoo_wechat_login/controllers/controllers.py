# -*- coding: utf-8 -*-

import base64
import logging
import hashlib
import json
import simplejson
import requests
import werkzeug.utils
from odoo import http
from odoo.http import request
from werkzeug.urls import url_encode
from werkzeug.exceptions import BadRequest

from odoo.exceptions import AccessDenied, ValidationError
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as Home
from odoo.addons.auth_oauth.controllers.main import OAuthController as Controller

_logger = logging.getLogger(__name__)


class WechatAuthController(http.Controller):
    def _get_wechat_config(self):
        """ 统一获取微信配置 """
        config = http.request.env['ir.config_parameter'].sudo()
        return {
            'appid': config.get_param('odoo_wechat_login.appid'),
            'secret': config.get_param('odoo_wechat_login.appsecret'),
            'token': config.get_param('odoo_wechat_login.token')
        }

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
    @http.route('/form', type='http', auth='public', website=True)
    def handle_wechat_auth(self, code=None, state=None, **kwargs):
        """ 处理微信授权回调 """
        try:
            _logger.info("=== 微信授权回调开始 ===")
            _logger.info(f"接收参数 - code: {code}, state: {state}")

            if not code:
                _logger.error("缺少code参数")
                return self._error_response("授权失败：缺少必要参数")


            # 获取微信配置
            config = self._get_wechat_config()
            if not all([config['appid'], config['secret']]):
                _logger.error("微信配置不完整")
                return self._error_response("系统配置错误")

            # 1. 获取access_token
            token_url = (
                f"https://api.weixin.qq.com/sns/oauth2/access_token?"
                f"appid={config['appid']}&"
                f"secret={config['secret']}&"
                f"code={code}&"
                f"grant_type=authorization_code"
            )

            _logger.info(f"请求Token URL: {token_url.split('secret=')[0]}...")  # 安全日志
            token_resp = requests.get(token_url, timeout=10)
            token_data = token_resp.json()
            _logger.info(f"Token响应: { {k: v for k, v in token_data.items() if k != 'access_token'} }")  # 隐藏敏感信息

            if 'errcode' in token_data:
                _logger.error(f"获取Token失败: {token_data}")
                return self._error_response(f"微信授权失败（错误代码：{token_data.get('errcode')}）")

            # 2. 获取用户信息
            user_info_url = (
                f"https://api.weixin.qq.com/sns/userinfo?"
                f"access_token={token_data['access_token']}&"
                f"openid={token_data['openid']}&"
                f"lang=zh_CN"
            )

            _logger.info(f"请求用户信息URL: {user_info_url.split('access_token=')[0]}...")
            user_resp = requests.get(user_info_url, timeout=5)
            user_data = user_resp.json()
            _logger.info(f"用户信息原始响应: { {k: v for k, v in user_data.items() if k != 'headimgurl'} }")

            if 'errcode' in user_data:
                _logger.error(f"获取用户信息失败: {user_data}")
                return self._error_response("无法获取用户信息")

            # 3. 处理用户数据
            wechat_user = {
                'openid': user_data.get('openid'),
                'unionid': user_data.get('unionid', ''),
                'nickname': user_data.get('nickname', ''),
                'sex': user_data.get('sex', 0),
                'province': user_data.get('province', ''),
                'city': user_data.get('city', ''),
                'country': user_data.get('country', ''),
                'headimgurl': user_data.get('headimgurl', ''),
                'privilege': user_data.get('privilege', [])
            }

            # 安全日志（不显示敏感信息）
            _logger.info("=== 用户数据摘要 ===")
            _logger.info(f"OpenID: {wechat_user['openid'][:6]}...")
            _logger.info(f"UnionID: {wechat_user['unionid'][:6] if wechat_user['unionid'] else '无'}")
            _logger.info(f"昵称: {wechat_user['nickname']}")
            _logger.info(f"性别: {['未知', '男', '女'][wechat_user['sex']]}")
            _logger.info(f"地区: {wechat_user['country']}-{wechat_user['province']}-{wechat_user['city']}")

            # 存储到session
            http.request.session['wechat_user'] = wechat_user
            _logger.info("用户数据已存入session")

            return self._redirect_to_form()


        except requests.Timeout:
            _logger.error("微信API请求超时")
            return self._error_response("微信服务器响应超时，请稍后重试")
        except Exception as e:
            _logger.exception("微信授权处理异常")
            return self._error_response(f"系统错误: {str(e)}")

    def _redirect_to_form(self):
        """ 跳转到表单页 """
        if not http.request.session.get('wechat_user'):
            return self._error_response("会话信息丢失")
        return http.request.redirect("/forms")

    def _error_response(self, message):
        """ 统一错误响应 """
        _logger.error(f"错误响应: {message}")
        return http.request.render('wechat_login.error_template', {
            'error_message': message
        })

    # @http.route('/forms', type='http', auth='public', website=True)
    # def display_form(self, **kwargs):
    #     """ 直接渲染Website Builder创建的页面 """
    #     user_data = http.request.session.get('wechat_user', {})
    #     if not user_data:
    #         return "❌ 请通过微信公众号菜单访问本页面"
    #     return http.request.render('website.alitec-forms')  # 使用实际存在的页面XML ID

    @http.route('/forms', type='http', auth='public', website=True)
    def display_form(self, **kwargs):
        """
        核心功能：
        1. 验证微信授权状态
        2. 传递用户数据到模板
        3. 渲染Website Builder创建的页面
        """
        wechat_user = http.request.session.get('wechat_user')

        if not wechat_user:
            _logger.warning("未授权访问尝试，来源IP: %s", http.request.httprequest.remote_addr)
            return self._error_response("请通过微信公众号菜单访问本页面")

        _logger.info("渲染表单页，OpenID: %s", wechat_user.get('openid', '未知'))

        try:
            # 确保使用正确的模板XML ID
            return http.request.render('website.alitec-forms', {
                'wechat_user': wechat_user,
                'hide_header_footer': True  # 可选：隐藏页头页尾
            })
        except ValueError as e:
            _logger.error("模板渲染失败: %s", str(e))
            return self._error_response("页面加载失败，请联系管理员")


class FormSubmissionController(http.Controller):
    @http.route('/forms/submit', type='http', auth='public', website=True, csrf=False)
    def handle_form_submission(self, **post_data):
        """ 安全处理表单提交 """
        try:
            # 获取微信用户数据
            wechat_user = http.request.session.get('wechat_user', {})
            _logger.info("=== 表单提交开始 ===")
            _logger.info("提交数据: %s", {k: v for k, v in post_data.items() if k != 'csrf_token'})
            _logger.info("微信用户数据: %s", wechat_user)

            # 基础验证
            if not wechat_user.get('openid'):
                return "❌ 请通过微信授权访问本页面"

            if not post_data.get('phone'):
                return "❌ 手机号不能为空"

            # 准备用户数据 (只包含res.users存在的字段)
            user_vals = {
                'name': post_data.get('name', wechat_user.get('nickname', '微信用户')),
                'login': post_data.get('phone'),  # 使用手机号作为登录账号
                'phone': post_data.get('phone'),
                'comment': f"WeChat Info: OpenID={wechat_user.get('openid')}, Nickname={wechat_user.get('nickname')}"
            }

            # 添加微信相关字段（需先在res.users模型中添加这些字段）
            # 注意：实际使用前需要先添加这些字段到模型中
            # extra_fields = {
            #     'wechat_openid': wechat_user.get('openid'),
            #     'wechat_unionid': wechat_user.get('unionid'),
            #     'wechat_nickname': wechat_user.get('nickname'),
            #     'wechat_sex': str(wechat_user.get('sex', 0)),
            #     'wechat_province': wechat_user.get('province'),
            #     'wechat_city': wechat_user.get('city')
            # }
            #
            # # 过滤掉None值
            # user_vals.update({k: v for k, v in extra_fields.items() if v})

            _logger.info("准备创建用户的数据: %s", user_vals)

            # 创建用户
            user = http.request.env['res.users'].sudo().create(user_vals)

            _logger.info("✅ 用户创建成功，ID: %s", user.id)
            return "✅ 注册成功！用户ID: {}".format(user.id)

        except Exception as e:
            _logger.exception("用户创建失败")
            return "❌ 注册失败: {}".format(str(e))

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
