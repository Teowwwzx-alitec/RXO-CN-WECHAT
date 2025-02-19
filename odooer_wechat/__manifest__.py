# -*- coding: utf-8 -*-
{
    'name': '微信公众号',
    'version': '17.0.1.0',
    'license': 'LGPL-3',
    'category': 'ODOOER/WX',
    'sequence': 1,
    'summary': '基于 aiohttp 的微信公众号接口',
    'description': '''
        基于 aiohttp 的微信公众号接口, 仅实现小部分 API 使用全部api, 可使用 wechatpy 或 werobot 替代 client。
    ''',
    'author': 'AaronZZH',
    'price': 9.99,
    'currency': 'USD',
    'website': 'https://www.aaronzzh.cn',
    'depends': ['base'],
    'external_dependencies': {
        # wechatpy 公众号消息解析，也可作为客户端。本模块中使用 aiohttp 实现微信公众号客户端
        'python': ['aiohttp', 'wechatpy', 'diskcache'],
    },
    'data': [
        'security/ir.model.access.csv',
        'data/wechat_data.xml',
        'views/wx_user_views.xml',
        'views/wx_config_views.xml',
        'views/wechat_menus.xml',
    ],
    'demo': [
    ],
    'assets': {
        'web.assets_backend': [
            'odooer_wechat/static/src/components/**/*',
        ]
    },
    'images': ['static/description/screenshot.png'],
    'auto_install': False,
    'application': False,
    'installable': True,
}
