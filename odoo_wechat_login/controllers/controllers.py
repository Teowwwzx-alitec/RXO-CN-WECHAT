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
    def send_wechat_message(self, openid, message, appid, appsecret):
        """
        Instance method: we include `self` so it can be called as self.send_wechat_message(...)
        """
        _logger.info("Preparing to send WeChat message to %s", openid)

        token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
        token_resp = requests.get(token_url, timeout=5)
        token_data = token_resp.json()
        if 'access_token' not in token_data:
            _logger.error("Failed to retrieve official account token: %s", token_data)
            return

        access_token = token_data['access_token']
        send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"
        payload = {
            "touser": openid,
            "msgtype": "text",
            "text": {
                "content": message
            }
        }
        headers = {'Content-Type': 'application/json'}
        resp = requests.post(send_url, data=simplejson.dumps(payload), headers=headers, timeout=5)
        resp_data = resp.json()
        if resp_data.get('errcode') == 0:
            _logger.info("WeChat message sent successfully to %s", openid)
        else:
            _logger.error("WeChat message failed: %s", resp_data)

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


    def send_wechat_message(openid, message, appid, appsecret):
        """
        Sends a simple text message to a user via WeChat Official Account (Service Account).
        """
        # 1) Retrieve or store your official account access_token. Usually, you’d store
        #    and refresh this token in your Odoo system parameters to avoid repeated requests.
        #    For simplicity, we’ll fetch a fresh token here:

        token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
        token_resp = requests.get(token_url, timeout=5)
        token_data = token_resp.json()
        if 'access_token' not in token_data:
            _logger.error("Failed to retrieve official account token: %s", token_data)
            return

        access_token = token_data['access_token']

        # 2) Call the Customer Service Message API
        send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"
        payload = {
            "touser": openid,
            "msgtype": "text",
            "text": {
                "content": message
            }
        }
        headers = {'Content-Type': 'application/json'}
        resp = requests.post(send_url, data=simplejson.dumps(payload), headers=headers, timeout=5)
        resp_data = resp.json()
        if resp_data.get('errcode') == 0:
            _logger.info("WeChat message sent successfully to %s", openid)
        else:
            _logger.error("WeChat message failed: %s", resp_data)


    @http.route('/forms/submit', type='http', auth='public', website=True, csrf=False)
    def handle_form_submission(self, **post_data):
        """ 安全处理表单提交并在成功后创建系统用户与微信扩展档案 """
        try:
            wechat_user = http.request.session.get('wechat_user', {})
            _logger.info("=== 表单提交调试模式启动 ===")

            # 1) 验证会话中的微信用户信息
            openid = wechat_user.get('openid')
            if not openid:
                _logger.error("会话中未找到微信用户信息")
                return request.redirect('/error?error_message=' + werkzeug.utils.url_quote("会话信息丢失，请重新授权"))

            # 2) 获取并验证表单数据
            phone = post_data.get('phone', '').strip()
            name = post_data.get('name', '').strip()
            email = post_data.get('email', '').strip()
            wish = post_data.get('wish', '').strip()

            if not phone or len(phone) < 8:
                _logger.error("无效的手机号")
                return request.redirect('/error?error_message=' + werkzeug.utils.url_quote("无效的手机号，请检查后重试"))

            if not email:
                _logger.info("缺少邮件地址")
                return request.redirect('/error?error_message=' + werkzeug.utils.url_quote("缺少邮件地址，请检查后重试"))

            # 3) 检查是否已存在该微信用户档案 (根据 openid)
            existing_profile = request.env['wechat.user.profile'].sudo().search([
                ('openid', '=', openid)
            ], limit=1)

            if existing_profile:
                # 如果已存在, 直接使用现有用户并跳转到成功页 (或自行决定更新/跳转逻辑)
                _logger.info("微信用户已存在，使用现有记录 user_id: %s", existing_profile.user_id.id)
                return request.redirect('/success?user_id=%s' % existing_profile.user_id.id)
            else:
                # 4) 不存在则创建一个新的门户用户 (res.users)
                portal_group = request.env.ref('base.group_portal')
                user_vals = {
                    'name': name,
                    'login': email,
                    'email': email,
                    'password': '12345',  # 建议生成或提示用户设置密码
                    'groups_id': [(6, 0, [portal_group.id])],
                    # 'wechat_openid': openid,
                }
                user = request.env['res.users'].sudo().create(user_vals)
                _logger.info("成功创建系统用户: %s (ID: %s)", user.login, user.id)

                # 2. 创建对应的微信用户档案
                profile_vals = {
                    'user_id': user.id,
                    'openid': openid,
                    'nickname': wechat_user.get('nickname'),
                    'sex': str(wechat_user.get('sex', 0)),
                    'city': wechat_user.get('city', ''),
                    'province': wechat_user.get('province', ''),
                    'headimgurl': wechat_user.get('headimgurl', ''),
                    'privilege': simplejson.dumps(wechat_user.get('privilege', [])),
                    'raw_data': simplejson.dumps(wechat_user),
                    'wish': wish,
                }
                new_profile = request.env['wechat.user.profile'].sudo().create(profile_vals)
                _logger.info("微信用户档案已创建, profile ID: %s", new_profile.id)


            # 6) 成功后发送一条微信消息 (可选)
            config = self._get_wechat_config()  # reuse the method from your controller
            success_msg = f"提交成功！感谢您，{user.name or '用户'}。"
            self.send_wechat_message(
                openid=openid,
                message=success_msg,
                appid=config['appid'],
                appsecret=config['secret']
            )

            # 6) 跳转到成功页并附加 user_id
            return request.redirect('/success?user_name=%s&phone=%s' % (
                werkzeug.utils.url_quote(user.name),
                werkzeug.utils.url_quote(user.login),
            ))

            # return request.redirect('/error?error_message=' + werkzeug.utils.url_quote(f"系统错误:"))

        except Exception as e:
            _logger.exception("表单提交处理异常")
            return request.redirect('/error?error_message=' + werkzeug.utils.url_quote(f"系统错误: {str(e)}"))


    # @http.route('/error', type='http', auth='public', website=True)
    # def error_page(self, **kw):
    #     error_message = kw.get('error_message', '发生错误')
    #     return request.render('wechat_login.error_template', {
    #         'error_message': error_message
    #     })
    #
    # @http.route('/sucess', type='http', auth='public', website=True)
    # def success_page(self, **kw):
    #     return request.render('wechat_login.success_template', {})


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
