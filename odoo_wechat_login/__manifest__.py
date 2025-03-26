# -*- coding: utf-8 -*-
{
    "name": "Wechat login 微信登录",
    "description": """
    功能介绍
    ==============
    * 微信网页扫码登录
    """,
    "category": "Extra Tools",
    "author": "soong bo",
    "license": "AGPL-3",
    "version": "17.0.0.1.0",
    "depends": ["auth_oauth"],
    "external_dependencies": {"python": ["simplejson"]},
    "data": [
        "data/login_data.xml",
        "views/res_users_views.xml",
        "views/res_config_settings_views.xml",
        # "views/templates_views.xml"
    ],
    "installable": True,
    "auto_install": False,
    "application": True,
    "price": 50,
    "currency": "USD",
    "images": ["static/description/icon.png"],
}
