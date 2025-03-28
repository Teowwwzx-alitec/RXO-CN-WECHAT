# -*- coding: utf-8 -*-

import base64
import logging
import hashlib
import json
import simplejson
import requests
import werkzeug.utils
from odoo import http
from datetime import datetime
from odoo.http import request
from werkzeug.urls import url_encode
from werkzeug.exceptions import BadRequest

from odoo.exceptions import AccessDenied, ValidationError
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as Home
from odoo.addons.auth_oauth.controllers.main import OAuthController as Controller

_logger = logging.getLogger(__name__)


class WechatAuthController(http.Controller):
    @http.route('/wechat/test_message', type='http', auth='public')
    def test_wechat_message(self, **kwargs):
        """
        微信消息发送测试端点
        访问URL: /wechat/test_message?openid=TEST_OPENID
        """
        try:
            openid = kwargs.get('openid', 'ojUNAwrfPBJGzGz-6GQ70gUoyIwQ')  # 测试用openid
            test_message = "测试消息 - 您的表单已成功提交！感谢您参与测试。"

            _logger.info("=== 开始微信消息发送测试 ===")

            # 获取微信配置
            config = self._get_wechat_config()
            if not all([config['appid'], config['secret']]):
                return "微信配置不完整，请检查系统参数设置"

            # 测试不同编码的消息
            test_cases = [
                ("纯英文消息", "Test message: Form submitted successfully!"),
                ("纯中文消息", "测试消息：表单提交成功！"),
                ("中英混合", "Test成功! 您的form已提交"),
                ("特殊字符", "100% 完成 & 感谢支持！"),
                ("长消息", "这是一条比较长的测试消息，" * 5)
            ]

            results = []
            for case_name, message in test_cases:
                success = self._send_test_message(
                    openid=openid,
                    message=message,
                    appid=config['appid'],
                    appsecret=config['secret'],
                    case_name=case_name
                )
                results.append(f"{case_name}: {'成功' if success else '失败'}")

            return "<br/>".join([
                "<h3>微信消息发送测试结果</h3>",
                f"目标OpenID: {openid}",
                f"AppID: {config['appid']}",
                "<hr/>",
                *results,
                "<hr/>",
                "检查Odoo日志获取详细调试信息"
            ])

        except Exception as e:
            _logger.exception("测试异常")
            return f"测试失败: {str(e)}"

    def _send_test_message(self, openid, message, appid, appsecret, case_name):
        """ 发送测试消息并记录详细日志 """
        try:
            _logger.info("=== 测试用例 [%s] ===", case_name)
            _logger.info("原始消息: %s", message)

            # 1. 获取access_token
            token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
            token_resp = requests.get(token_url, timeout=5)
            token_data = token_resp.json()

            if 'access_token' not in token_data:
                _logger.error("获取Token失败: %s", token_data)
                return False

            access_token = token_data['access_token']

            # 2. 准备消息体（确保UTF-8编码）
            payload = {
                "touser": openid,
                "msgtype": "text",
                "text": {"content": message}
            }

            # 3. 发送请求（使用simplejson确保中文不转义）
            send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"
            headers = {'Content-Type': 'application/json; charset=utf-8'}

            _logger.debug("发送Payload: %s", payload)

            resp = requests.post(
                send_url,
                data=simplejson.dumps(payload, ensure_ascii=False).encode('utf-8'),
                headers=headers,
                timeout=10
            )

            resp_data = resp.json()
            _logger.debug("微信响应: %s", resp_data)

            if resp_data.get('errcode') == 0:
                _logger.info("✅ 测试成功 - %s", case_name)
                return True
            else:
                _logger.error("❌ 测试失败 - %s | 错误: %s",
                              case_name, resp_data.get('errmsg', '未知错误'))
                return False

        except Exception as e:
            _logger.exception("测试用例 [%s] 异常", case_name)
            return False

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

            # 4) 如果 openid 不存在, 则检查是否已有相同 email 的用户
            existing_user = request.env['res.users'].sudo().search([
                ('login', '=', email)
            ], limit=1)

            if existing_user:
                _logger.info("用户已存在 (email=%s)，使用现有用户: %s (ID: %s)", email, existing_user.login,
                             existing_user.id)
                return request.redirect('/success?user_id=%s' % existing_user.id)

            # 5) 如果连用户都不存在，则创建一个新的门户用户 (res.users)
            portal_group = request.env.ref('base.group_portal')
            user_vals = {
                'name': name,
                'login': email,
                'email': email,
                'password': '12345',  # 建议生成或提示用户设置密码
                'groups_id': [(6, 0, [portal_group.id])],
            }
            user = request.env['res.users'].sudo().create(user_vals)
            _logger.info("成功创建系统用户: %s (ID: %s)", user.login, user.id)

            # 创建对应的微信用户档案
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

            # 测试不同编码的消息
            test_cases = [
                ("纯英文消息", "Test message: Form submitted successfully!"),
                ("纯中文消息", "测试消息：表单提交成功！"),
                ("中英混合", "Test成功! 您的form已提交"),
                ("特殊字符", "100% 完成 & 感谢支持！"),
                ("长消息", "这是一条比较长的测试消息，" * 5)
            ]



            # 6) 成功后发送一条微信消息 (可选)
            config = self._get_wechat_config()
            # success_msg = (
            #     "表单提交成功通知\n"
            #     "----------------\n"
            #     f"姓名：{user.name or '未填写'}\n"
            #     f"电话：{phone}\n"
            #     "感谢您的提交，我们将尽快处理！"
            # )
            success_msg = ("纯英文消息", "Test message: Form submitted successfully!"),

            # 添加发送频率检查
            last_sent = http.request.session.get('last_wechat_msg_time')
            if last_sent and (datetime.now() - last_sent).seconds < 60:
                _logger.warning("消息发送过于频繁，已跳过")
            else:
                WechatAuthController.send_wechat_message(
                    openid=openid,
                    message=success_msg,
                    appid=config['appid'],
                    appsecret=config['secret']
                )
                http.request.session['last_wechat_msg_time'] = datetime.now()

            # 6) 跳转到成功页并附加 user_id
            return request.redirect('/success?user_name=%s&phone=%s' % (
                werkzeug.utils.url_quote(user.name),
                werkzeug.utils.url_quote(user.login),
            ))

        except Exception as e:
            _logger.exception("表单提交处理异常")
            return request.redirect('/error?error_message=' + werkzeug.utils.url_quote(f"系统错误: {str(e)}"))

    @staticmethod
    def send_wechat_message(openid, message, appid, appsecret):
        """
        Send a simple text message to a user via WeChat Official Account (Service Account).
        Uses ensure_ascii=False so that the payload logs are more human-readable in Python.
        """
        try:
            # 1. 消息预处理
            message = message.strip()
            if len(message.encode('utf-8')) > 600:  # 约200个汉字
                message = message[:150] + "..."  # 截断过长的消息

            # 2. 替换特殊字符（保持可读性）
            safe_message = (
                message.replace('&', '和')
                .replace('<', '(')
                .replace('>', ')')
                .replace('"', "'")
            )

            # 3. 获取access_token（带重试机制）
            token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
            token_resp = requests.get(token_url, timeout=5)
            token_data = token_resp.json()

            if 'access_token' not in token_data:
                _logger.error("获取Token失败: %s", token_data)
                return False

            # 4. 构造安全的payload
            payload = {
                "touser": openid,
                "msgtype": "text",
                "text": {"content": safe_message}
            }

            # 5. 发送请求（使用更安全的json处理）
            send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={token_data['access_token']}"
            resp = requests.post(
                send_url,
                json=payload,  # 自动处理编码
                headers={'Content-Type': 'application/json'},
                timeout=10
            )

            resp_data = resp.json()
            if resp_data.get('errcode') == 0:
                _logger.info("消息发送成功 | OpenID: %s...", openid[:6])
                return True
            else:
                error_msg = resp_data.get('errmsg', '未知错误')
                _logger.error("发送失败 | 错误: %s | 消息: %s", error_msg, safe_message)

                # 处理频率限制错误
                if "response count limit" in error_msg:
                    _logger.warning("⚠️ 达到微信消息频率限制，建议：")
                    _logger.warning("1. 减少发送频率")
                    _logger.warning("2. 合并多条消息")
                    _logger.warning("3. 使用模板消息替代客服消息")

                return False

        except Exception as e:
            _logger.exception("消息发送异常")
            return False