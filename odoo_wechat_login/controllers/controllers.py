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
    # --- 配置助手 ---
    def _get_wechat_config(self):
        """ 从 Odoo 系统参数中获取微信 AppID 和 Secret """
        config = request.env['ir.config_parameter'].sudo()
        appid = config.get_param('odoo_wechat_login.appid')
        appsecret = config.get_param('odoo_wechat_login.appsecret')
        if not appid or not appsecret:
            _logger.error("系统中缺少微信 AppID 或 AppSecret。")
            return None  # 返回 None 表示配置缺失
        return {'appid': appid, 'secret': appsecret}

    # --- 微信服务器验证端点 ---
    @http.route('/wechat-verify', type='http', auth='public', methods=['GET'], csrf=False)
    def verify_wechat_token(self, signature=None, timestamp=None, nonce=None, echostr=None, **kwargs):
        """ 处理来自微信服务器的初始 Token 验证 """
        # 安全地获取验证 Token (替换硬编码值)
        token = request.env['ir.config_parameter'].sudo().get_param('odoo_wechat_login.token',
                                                                    "DEFAULT_FALLBACK_TOKEN")  # 示例备用值
        if not token:
            _logger.error("系统中未设置微信验证 Token。")
            return "配置错误"  # Configuration Error

        try:
            tmp_list = sorted([token, timestamp or '', nonce or ''])
            tmp_str = ''.join(tmp_list).encode('utf-8')
            hash_str = hashlib.sha1(tmp_str).hexdigest()

            if hash_str == signature:
                _logger.info("✅ 微信 Token 验证成功。")
                return echostr or ''  # 按微信要求返回 echostr
            else:
                _logger.error(f"❌ Token 验证失败 | 收到签名: {signature} | 计算签名: {hash_str}")
                return "验证失败"  # Verification Failed
        except Exception as e:
            _logger.exception("微信 Token 验证过程中出错。")
            return "验证错误"  # Verification Error

    # --- 微信 OAuth 回调处理器 ---
    @http.route('/form', type='http', auth='public', website=True, csrf=False)  # 考虑 csrf=True (如果可能)
    def handle_wechat_auth(self, code=None, state=None, **kwargs):
        """ 处理用户授权后从微信重定向回来的请求 """
        try:
            _logger.info(f"=== 微信 OAuth 回调开始 - Code: {'有' if code else '无'}, State: {state} ===")

            # ** 重要操作：实现 State 验证 **
            # 1. 在重定向用户到微信之前生成唯一的 state 值，并存入 session。
            # 2. 对比收到的 'state' 参数和 session 中的值。如果不匹配则中止（防止 CSRF 攻击）。
            # saved_state = request.session.pop('oauth_state', None)
            # if not state or not saved_state or state != saved_state:
            #     _logger.warning("OAuth state 验证失败。可能是 CSRF 攻击。")
            #     return self._error_response("授权失败（无效的 State）。请重试。")

            if not code:
                _logger.error("授权失败：微信回调中缺少 'code' 参数。")
                return self._error_response("授权失败：缺少必要参数。")

            config = self._get_wechat_config()
            if not config:
                return self._error_response("系统配置错误（缺少微信凭证）。")

            # 1. 用 code 换取 access_token 和 openid
            token_url = (
                f"https://api.weixin.qq.com/sns/oauth2/access_token?"
                f"appid={config['appid']}&secret={config['secret']}&"
                f"code={code}&grant_type=authorization_code"
            )
            _logger.info(f"请求 OAuth token...")
            token_resp = requests.get(token_url, timeout=10)
            token_resp.raise_for_status()  # 抛出 HTTP 错误
            token_data = token_resp.json()

            if token_data.get('errcode'):
                _logger.error(f"获取 OAuth token 失败: {token_data}")
                return self._error_response(f"微信授权失败（错误码：{token_data.get('errcode')}）。")

            access_token = token_data.get('access_token')
            openid = token_data.get('openid')
            if not access_token or not openid:
                _logger.error(f"OAuth token 响应中缺少 access_token 或 openid: {token_data}")
                return self._error_response("未能获取必要的微信凭证。")

            # 2. 使用 access_token 获取用户信息
            user_info_url = (
                f"https://api.weixin.qq.com/sns/userinfo?"
                f"access_token={access_token}&openid={openid}&lang=zh_CN"  # 使用简体中文
            )
            _logger.info(f"请求用户信息，OpenID: {openid[:6]}...")
            user_resp = requests.get(user_info_url, timeout=10)
            user_resp.raise_for_status()  # 抛出 HTTP 错误
            # 显式解码以正确处理字符
            user_data = simplejson.loads(user_resp.content.decode('utf-8'))

            if user_data.get('errcode'):
                _logger.error(f"获取用户信息失败: {user_data}")
                return self._error_response("未能从微信获取用户信息。")

            # 3. 准备用户数据并存入 session
            wechat_user = {
                'openid': user_data.get('openid'),
                'unionid': user_data.get('unionid'),  # 如果可用，存储 unionid
                'nickname': user_data.get('nickname'),
                'sex': user_data.get('sex'),
                'province': user_data.get('province'),
                'city': user_data.get('city'),
                'country': user_data.get('country'),
                'headimgurl': user_data.get('headimgurl'),
                'privilege': user_data.get('privilege', [])  # 确保默认值是列表
            }
            _logger.info(f"收到用户信息: 昵称='{wechat_user['nickname']}', OpenID={wechat_user['openid'][:6]}...")

            request.session['wechat_user'] = wechat_user
            _logger.info("微信用户数据已存入 session。")
            return self._redirect_to_form()  # 重定向到表单页面

        except requests.exceptions.Timeout:
            _logger.error("OAuth 流程中请求微信 API 超时。")
            return self._error_response("微信服务器响应超时，请稍后重试。")
        except requests.exceptions.RequestException as e:
            _logger.error(f"微信 OAuth 流程中发生网络错误: {e}")
            return self._error_response("与微信通信时发生网络错误，请重试。")
        except Exception as e:
            _logger.exception("微信授权回调过程中发生意外错误。")
            return self._error_response(f"发生意外的系统错误: {str(e)}")

    # --- 重定向助手 ---
    def _redirect_to_form(self):
        """ 重定向用户到数据录入表单页面 """
        if not request.session.get('wechat_user'):
            # 理想情况下，如果 session 管理正确，此情况不应发生
            _logger.warning("尝试重定向到表单，但 session 数据丢失。")
            return self._error_response("会话信息丢失，请重新开始流程。")
        return request.redirect("/forms")

    # --- 错误响应助手 ---
    def _error_response(self, message="发生意外错误。"):
        """ 重定向到通用的 /error 页面并附带消息 """
        _logger.error(f"错误响应触发: {message}")
        try:
            # 确保消息是字符串
            message_str = str(message)
            error_param = werkzeug.utils.url_quote(message_str)
            return request.redirect(f'/error?error_message={error_param}')
        except Exception as e_redir:
            _logger.exception("重定向到错误页面失败。")
            # 如果重定向失败，返回纯文本响应
            return werkzeug.wrappers.Response(f"系统错误: {message}", status=500, content_type='text/plain')

    # --- 表单显示端点 ---
    @http.route('/forms', type='http', auth='public', website=True)
    def display_form(self, **kwargs):
        """ 显示用户数据录入表单 """
        wechat_user = request.session.get('wechat_user')

        if not wechat_user or not wechat_user.get('openid'):
            _logger.warning("未授权访问 /forms 页面。 IP: %s", request.httprequest.remote_addr)
            # 重定向到信息页或错误页，而不是显示表单
            return self._error_response("请通过微信授权链接访问此页面。")

        _logger.info("为 OpenID 渲染表单页面: %s", wechat_user.get('openid')[:6])

        try:
            # 渲染你的特定表单模板 (例如 'website.alitec-forms')
            return request.render('website.alitec-forms', {  # 确保 'website.alitec-forms' 是正确的模板名
                'wechat_user': wechat_user,
                'hide_header_footer': True  # 可选：如果你的模板使用此参数
            })
        except Exception as e:  # 捕获潜在的渲染错误
            _logger.exception("渲染表单模板失败。")
            return self._error_response("页面加载错误，请联系支持人员。")

    # --- 表单提交处理器 (优化逻辑) ---
    @http.route('/forms/submit', type='http', auth='public', website=True, csrf=False)  # 考虑 csrf=True
    def handle_form_submission(self, **post_data):
        """ 处理表单提交，查找/创建/绑定用户，并重定向。 """
        try:
            # 1) 从 session 获取微信信息
            wechat_user = request.session.get('wechat_user', {})
            openid = wechat_user.get('openid')
            if not openid:
                _logger.error("表单提交期间 Session 缺少微信 OpenID。")
                return self._error_response("会话信息丢失，请通过微信重新授权。")

            _logger.info(f"=== 表单提交开始 - OpenID: {openid[:6]}... ===")

            # 2) 获取并验证表单数据
            phone = post_data.get('phone', '').strip()
            email = post_data.get('email', '').strip().lower()  # 规范化 email
            name = post_data.get('name', '').strip()  # 获取姓名，稍后可能使用
            wish = post_data.get('wish', '').strip()  # 获取可选的愿望字段

            # 基本验证 (根据需要添加更多)
            if not phone or len(phone) < 8:  # 基本电话检查
                return self._error_response("需要提供有效的电话号码。")
            if not email or '@' not in email or '.' not in email:  # 基本 email 检查
                return self._error_response("需要提供有效的电子邮件地址。")
            _logger.info(f"表单数据验证通过 - Email: {email}, Phone: {phone}")

            config = self._get_wechat_config()
            if not config:  # 检查发送消息所需的配置
                return self._error_response("系统配置错误（缺少微信凭证）。")

            user_to_process = None
            outcome = None
            success_msg = ""  # 成功消息

            # --- 逻辑步骤 1: 通过 wechat.user.profile 检查 OpenID ---
            existing_profile = request.env['wechat.user.profile'].sudo().search([
                ('openid', '=', openid)
            ], limit=1)

            if existing_profile and existing_profile.user_id:
                _logger.info(
                    f"找到 OpenID {openid[:6]} 的现有档案，已链接到用户 ID: {existing_profile.user_id.id}。结果: existing。")
                user_to_process = existing_profile.user_id
                outcome = 'existing'  # 结果为 '现有'
                success_msg = f"欢迎回来, {user_to_process.name}! 您的信息已注册。"
                # 可选: 如果 wechat_user 中的昵称/头像等已更改，则更新档案？
                # existing_profile.sudo().write({'nickname': wechat_user.get('nickname'), ...})

            # --- 逻辑步骤 2: 通过 res.users 检查 Email (如果 OpenID 不匹配) ---
            elif not user_to_process:  # 仅当步骤 1 未找到用户时继续
                existing_user = request.env['res.users'].sudo().search([
                    ('login', '=', email)  # 使用规范化的 email
                ], limit=1)

                if existing_user:
                    _logger.info(
                        f"通过 email {email} 找到现有用户 ID: {existing_user.id}。OpenID {openid[:6]} 尚未链接。现在绑定。结果: existing。")
                    user_to_process = existing_user
                    outcome = 'existing'  # 或 'linked' (如果你希望区分)

                    # ** 关键操作：创建档案以绑定微信 **
                    try:
                        profile_vals = self._prepare_profile_vals(wechat_user, user_to_process.id, openid, wish)
                        # 检查此 user_id 是否已存在档案但 openid 不同（不太可能但可能）
                        existing_profile_for_user = request.env['wechat.user.profile'].sudo().search(
                            [('user_id', '=', user_to_process.id)], limit=1)
                        if not existing_profile_for_user:
                            new_profile = request.env['wechat.user.profile'].sudo().create(profile_vals)
                            _logger.info(
                                f"已创建微信档案 (ID: {new_profile.id}) 以链接 OpenID {openid[:6]} 到用户 ID: {user_to_process.id}")
                        else:
                            _logger.warning(
                                f"用户 ID {user_to_process.id} 已有关联的微信档案 (ID: {existing_profile_for_user.id})。不会为 OpenID {openid[:6]} 创建新的。请检查潜在问题。")
                            # 决定如何处理：更新现有？报错？忽略？目前我们继续处理。

                        success_msg = f"您好 {user_to_process.name}! 我们已将您的微信账号关联到您现有的个人档案。"
                    except Exception as e_bind:
                        _logger.exception(
                            f"为用户 ID {user_to_process.id} / OpenID {openid[:6]} 创建/链接 wechat.user.profile 失败。")
                        return self._error_response(f"链接微信账号失败: {str(e_bind)}")

            # --- 逻辑步骤 3: 创建新用户 (如果 OpenID 和 Email 均不匹配) ---
            if not user_to_process:
                _logger.info(f"未找到 OpenID {openid[:6]} 的现有档案或 email {email} 的用户。正在创建新用户。结果: new。")
                outcome = 'new'  # 结果为 '新建'
                try:
                    # 确保 Portal 用户组存在
                    portal_group = request.env.ref('base.group_portal', raise_if_not_found=False)
                    if not portal_group:
                        _logger.error("找不到 Portal 用户组 ('base.group_portal')。")
                        return self._error_response("系统配置错误（用户组丢失）。")

                    # 先创建 Partner (最佳实践)
                    partner_vals = {'name': name or email, 'email': email, 'phone': phone, 'is_company': False}
                    partner = request.env['res.partner'].sudo().create(partner_vals)

                    # 创建链接到 Partner 的 User
                    user_vals = {
                        'name': name or email, 'login': email, 'phone': phone, 'active': True,
                        'groups_id': [(6, 0, [portal_group.id])], 'partner_id': partner.id
                        # ** 重要操作：安全处理密码（例如，使用 auth_signup 流程、随机密码，或如果仅限门户则无密码） **
                        # 'password': 'SECURE_PASSWORD_OR_REMOVE',
                    }
                    # 使用 context 可能可以避免稍后使用 signup token 时的密码重置邮件
                    new_user = request.env['res.users'].with_context(no_reset_password=True).sudo().create(user_vals)
                    user_to_process = new_user
                    _logger.info(f"已创建新用户 ID: {user_to_process.id} / Partner ID: {partner.id}")

                    # 创建链接到新用户的 Profile
                    profile_vals = self._prepare_profile_vals(wechat_user, user_to_process.id, openid, wish)
                    new_profile = request.env['wechat.user.profile'].sudo().create(profile_vals)
                    _logger.info(f"已为新用户 ID {user_to_process.id} 创建微信档案 (ID: {new_profile.id})")

                    success_msg = (
                        "注册成功!\n"
                        f"姓名: {user_to_process.name}\n邮箱: {email}\n电话: {phone}\n"
                        "感谢您提交信息。"
                    )
                except Exception as e_create:
                    _logger.exception("创建新用户/Partner/档案过程中出错。")
                    # 如果用户/档案创建失败，考虑清理已创建的 partner（更复杂）
                    return self._error_response(f"创建用户档案失败: {str(e_create)}")

            # --- 后续处理: 登录、发送消息、重定向 ---
            if user_to_process and outcome:
                # ** 重要操作：为 user_to_process 实现 Odoo 登录 **
                # 这部分对用户体验至关重要，但很大程度上取决于你的 Odoo 设置
                # (auth_oauth 助手、密码处理、session 管理)。
                # 使用 session authenticate 的示例 (需要密码或替代认证):
                # try:
                #     request.session.authenticate(request.env.cr.dbname, user_to_process.login, 'PASSWORD_PLACEHOLDER')
                #     _logger.info(f"用户 {user_to_process.login} 已成功认证到 Odoo session。")
                # except Exception as auth_err:
                #     _logger.error(f"创建/绑定后认证用户 {user_to_process.login} 失败: {auth_err}")
                #     # 决定这是否关键 - 也许无论如何都重定向？

                # 发送微信确认消息 (带频率限制)
                if success_msg:  # 仅当准备了消息时发送
                    last_sent_dt = request.session.get('last_wechat_msg_time')
                    # 确保 last_sent 是 datetime 对象再比较
                    can_send = True
                    if isinstance(last_sent_dt, datetime):
                        if (datetime.now() - last_sent_dt).total_seconds() < 60:  # 60 秒冷却时间
                            can_send = False
                            _logger.warning(f"因频率限制，已跳过为 OpenID {openid[:6]} 发送微信消息。")

                    if can_send:
                        # 调用静态方法
                        send_status = WechatAuthController.send_wechat_message(openid, success_msg, config['appid'],
                                                                               config['secret'])
                        if send_status:
                            request.session['last_wechat_msg_time'] = datetime.now()  # 存储 datetime 对象
                        else:
                            _logger.error(f"未能为 OpenID {openid[:6]} 发送微信确认消息...")
                            # 通常不关键，继续重定向

                # 重定向到成功页面
                redirect_url = '/success?outcome=%s&user_name=%s&phone=%s' % (
                    outcome,
                    werkzeug.utils.url_quote(user_to_process.name or '用户'),  # 确保 name 存在
                    werkzeug.utils.url_quote(user_to_process.phone or '')  # 确保 phone 存在
                )
                _logger.info(f"OpenID {openid[:6]} 处理完成。正在重定向到: {redirect_url}")
                return request.redirect(redirect_url)
            else:
                # 如果逻辑未能确定用户/结果，则返回备用错误
                _logger.error("表单处理完成，但未能确定用户或结果。OpenID: %s", openid[:6])
                return self._error_response("处理您的信息时发生意外错误。")

        except Exception as e:
            _logger.exception("表单提交处理器中发生未处理的异常。")
            return self._error_response(f"发生意外的系统错误: {str(e)}")

    # --- 准备档案数据的助手 ---
    def _prepare_profile_vals(self, wechat_user_session_data, user_id, openid, wish):
        """ 准备用于创建/更新 wechat.user.profile 的值字典的助手 """
        vals = {
            'user_id': user_id,
            'openid': openid,
            # 'unionid': wechat_user_session_data.get('unionid'), # 已移除 - 假设模型中不存在此字段
            'nickname': wechat_user_session_data.get('nickname'),
            'sex': str(wechat_user_session_data.get('sex', 0)),  # 如果模型字段是 Char，则存储为字符串
            'city': wechat_user_session_data.get('city', ''),
            'province': wechat_user_session_data.get('province', ''),
            # 'country': wechat_user_session_data.get('country', ''), # 已移除 - 假设模型中不存在此字段
            'headimgurl': wechat_user_session_data.get('headimgurl', ''),
            # 如果模型字段是 Text/Char，则将复杂类型存储为 JSON 字符串
            'privilege': simplejson.dumps(wechat_user_session_data.get('privilege', [])),
            'raw_data': simplejson.dumps(wechat_user_session_data),  # 存储所有原始数据
            'wish': wish,  # 存储表单中的愿望
        }
        # 可选: 仅当 unionid 存在于 session 数据中且你打算稍后添加该字段时，才条件性地添加 unionid
        # if 'unionid' in wechat_user_session_data and wechat_user_session_data['unionid']:
        #    # 如果你稍后向模型添加 'unionid' 字段，可以取消注释此行
        #    # vals['unionid'] = wechat_user_session_data['unionid']
        #    pass # 目前不对 unionid 做任何处理

        return vals

    # --- 微信消息发送 (静态方法) ---
    @staticmethod
    def send_wechat_message(openid, message, appid, appsecret):
        """
        使用微信客服接口发送文本消息。
        ** 紧急操作：实现 Access Token 缓存 **
        每次调用都获取 token 会很快达到频率限制。
        """
        # >>> Access Token 缓存逻辑占位符 <<<
        # 1. 尝试获取 appid 的缓存 token (例如, 从 ir.cache, 自定义模型, 文件)
        # 2. 如果存在有效 token，则使用它。
        # 3. 如果无效/过期: 使用 client_credential grant 获取新 token:
        #    token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
        #    检查响应，存储 token + 过期时间 (通常 7200秒)。
        # 4. 如果 token 获取失败，返回 False。
        # 5. 使用下面获取到的 access_token。

        # --- 模拟获取 (需要替换为缓存) ---
        try:
            _logger.info(f"正在获取新的微信 access_token 以发送消息 (AppID: {appid})... 需要缓存！")
            token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
            token_resp = requests.get(token_url, timeout=5)
            token_resp.raise_for_status()
            token_data = token_resp.json()
            access_token = token_data.get('access_token')
            if not access_token:
                _logger.error("获取用于发送消息的微信 Access Token 失败: %s", token_data.get('errmsg', '无错误消息'))
                return False
        except requests.exceptions.RequestException as token_err:
            _logger.error(f"获取微信 access token 时出错: {token_err}")
            return False
        # --- 结束模拟获取 ---

        try:
            # 确保消息是字符串
            message_content = str(message)

            payload = {
                "touser": openid,
                "msgtype": "text",
                "text": {"content": message_content}
            }
            send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"
            headers = {'Content-Type': 'application/json; charset=utf-8'}

            _logger.info(f"正在向 OpenID 发送微信消息: {openid[:6]}...")
            resp = requests.post(
                send_url,
                data=simplejson.dumps(payload, ensure_ascii=False).encode('utf-8'),  # ensure_ascii=False 以支持中文
                headers=headers,
                timeout=10  # 发送时使用更长的超时时间
            )
            resp.raise_for_status()  # 检查 HTTP 错误
            resp_data = resp.json()

            if resp_data.get('errcode') == 0:
                _logger.info(f"微信消息成功发送至 OpenID: {openid[:6]}.")
                return True
            else:
                # 记录特定的微信错误
                _logger.error("发送微信消息失败。错误码: %s, 消息: %s, OpenID: %s",
                              resp_data.get('errcode'), resp_data.get('errmsg', '未知微信错误'), openid[:6])
                return False

        except requests.exceptions.Timeout:
            _logger.error(f"向 OpenID 发送消息时微信 API 请求超时: {openid[:6]}.")
            return False
        except requests.exceptions.RequestException as req_err:
            _logger.error(f"向 OpenID {openid[:6]} 发送消息时微信 API 请求错误: {req_err}")
            return False
        except Exception as e:
            _logger.exception(f"向 OpenID 发送微信消息时发生意外错误: {openid[:6]}.")
            return False