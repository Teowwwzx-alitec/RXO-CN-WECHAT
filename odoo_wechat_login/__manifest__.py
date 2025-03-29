# -*- coding: utf-8 -*-
{
    "name": "Wechat Form Submission-微信表单处理",
    "summary": "通过微信网页扫码实现快速登录",
    "description": """
功能介绍
===============
* 实现微信网页扫码登录
* 支持获取微信用户基本信息
* 与 Odoo 的 OAuth 模块集成

详细信息请参阅官方微信登录文档：
https://developers.weixin.qq.com/doc/oplatform/Website_App/WeChat_Login/Wechat_Login.html
    """,
    "category": "Extra Tools",
    "author": "soong bo",
    "license": "AGPL-3",
    "version": "17.0.0.1.0",
    "depends": ["auth_oauth"],
    "external_dependencies": {
        "python": ["simplejson"]
    },
    "data": [
        "security/ir.model.access.csv",
        "data/login_data.xml",
        "views/res_users_views.xml",
        "views/res_config_settings_views.xml",
        "views/wechat_user_profile_views.xml"
    ],
    "installable": True,
    "auto_install": False,
    "application": True,
    "price": 50,
    "currency": "USD",
    "images": ["static/description/icon.png"],
}
