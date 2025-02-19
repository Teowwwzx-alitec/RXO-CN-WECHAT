import logging

_logger = logging.getLogger(__name__)


def subscribe(request, message):
    _logger.info('>>> wx msg: %s', message.__dict__)
    entry = request.entry
    openid = message.source

    info = entry.client.user.get(openid)
    info['group_id'] = str(info['groupid'])
    Follower = request.env['wx.user'].sudo()
    follower = Follower.search([('openid', '=', openid)])
    if not follower.exists():
        Follower.create(info)
    else:
        follower.write({'subscribe': True})

    return entry.subscribe_auto_msg if entry.subscribe_auto_msg else '欢迎关注!'


def unsubscribe(request, message):
    openid = message.source
    Follower = request.env['wx.user'].sudo()
    follower = Follower.search([('openid', '=', openid)])
    if follower.exists():
        follower.write({'subscribe': False})
    return ''
