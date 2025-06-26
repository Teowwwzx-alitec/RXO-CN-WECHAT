# -*- coding: utf-8 -*-
{
    "name": "Lark login",
    "description": """
    功能介绍
    ==============
    * Lark 网页扫码登录
    """,
    "category": "Extra Tools",
    "author": "soong bo",
    "license": "AGPL-3",
    "version": "17.0.0.1.0",
    "depends": ["auth_oauth", "web"],
    "external_dependencies": {"python": ["simplejson"]},
    "data": [
        "data/login_data.xml",
        "views/res_users_views.xml",
        "views/res_config_settings_views.xml",
        "views/lark_bind_templates.xml"
    ],
    "installable": True,
    "auto_install": False,
    "application": True,
    "price": 50,
    "currency": "USD",
    "images": ["static/description/icon.png"],
}