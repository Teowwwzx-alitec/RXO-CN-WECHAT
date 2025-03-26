import hashlib
import requests
from odoo import http
import logging
from urllib.parse import quote

_logger = logging.getLogger(__name__)


class WechatAuthController(http.Controller):

    # 微信Token验证接口（用于初次配置校验）
    @http.route('/form', type='http', auth='public', methods=['GET'], csrf=False)
    def verify_wechat_token(self, **kwargs):
        """ 微信服务器校验Token """
        signature = kwargs.get('signature', '')
        timestamp = kwargs.get('timestamp', '')
        nonce = kwargs.get('nonce', '')
        echostr = kwargs.get('echostr', '')

        token = "JIivg0Um8i0b6hGZ4bYQ3q"  # 必须与后台配置的Token一致

        # 按微信要求排序后拼接并加密
        tmp_list = sorted([token, timestamp, nonce])
        tmp_str = ''.join(tmp_list).encode('utf-8')
        hash_str = hashlib.sha1(tmp_str).hexdigest()

        if hash_str == signature:
            _logger.info("✅ 微信Token验证成功")
            return echostr  # 返回echostr完成验证
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
