# coding=utf-8
import re
import logging
import base64
import os
import datetime
import requests

from odoo.http import request
from odoo import SUPERUSER_ID


_logger = logging.getLogger(__name__)


def get_img_data(pic_url):
    headers = {
	'Accept': 'textml,application/xhtml+xml,application/xml;q=0.9,image/webp,/;q=0.8',
	'Accept-Encoding': 'gzip, deflate',
	'Accept-Language': 'zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4',
	'Cache-Control': 'no-cache',
	'Pragma': 'no-cache',
	'Connection': 'keep-alive',
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36',
    }
    r = requests.get(pic_url,headers=headers,timeout=50)
    return r.content


def input_handle(request, message):
    wxEntry = request.entry
    serviceid = message.target
    openid = message.source
    mtype = message.type
    _logger.info('>>> wx msg: %s'%message.__dict__)
    if message.id==wxEntry.OPENID_LAST.get(openid):
        _logger.info('>>> 重复的微信消息')
        return ''
    wxEntry.OPENID_LAST[openid] = message.id
    origin_content = ''
    attachment_ids = []
    if mtype=='image':
        pic_url = message.image
        media_id = message.__dict__.get('MediaId','')
        _logger.info(pic_url)
        _data = get_img_data(pic_url)
        _filename = datetime.datetime.now().strftime("%m%d%H%M%S") + os.path.basename(pic_url)
        attachment = request.env['ir.attachment'].sudo().create({
            'name': '__wx_image|%s'%media_id,
            'datas': base64.encodestring(_data),
            'datas_fname': _filename,
            'res_model': 'mail.compose.message',
            'res_id': int(0)
        })
        attachment_ids.append(attachment.id)
    elif mtype in ['voice']:
        media_id = message.media_id
        media_format = message.format
        r = wxEntry.client.media.download(media_id)
        _filename = '%s.%s'%(media_id,media_format)
        _data = r.content
        attachment = request.env['ir.attachment'].sudo().create({
            'name': '__wx_voice|%s'%message.media_id,
            'datas': base64.encodestring(_data),
            'datas_fname': _filename,
            'res_model': 'mail.compose.message',
            'res_id': int(0)
        })
        attachment_ids.append(attachment.id)
    elif mtype=='location':
        origin_content = '对方发送位置: %s 纬度为：%s 经度为：%s'%(message.label, message.location[0], message.location[1])
    elif mtype=='text':
        origin_content = message.content

    # 自动回复 #TODO
    # 客服 #TODO
    ret_msg = ''
    return ret_msg
