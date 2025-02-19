# -*- coding: utf-8 -*-

import logging
import werkzeug.wrappers
from wechatpy.utils import check_signature
from wechatpy import parse_message
from wechatpy import create_reply
from wechatpy.exceptions import InvalidSignatureException, InvalidAppIdException
from odoo import http
from odoo.http import request

from ..common import wx_entry
from .handlers.subscribe_event import subscribe, unsubscribe

_logger = logging.getLogger(__name__)


class WxController(http.Controller):
    @staticmethod
    def res_err(code):
        return werkzeug.wrappers.Response('Error', status=403, content_type='text/html;charset=utf-8')

    @http.route('/wx_handler', type='http', auth='none', methods=['GET', 'POST'], csrf=False)
    def handle(self, **kwargs):
        entry = wx_entry.wxenv(request.env)
        request.entry = entry
        self.crypto = entry.crypto_handle
        self.token = entry.wx_token
        _logger.info('>>> %s' % request.params)

        msg_signature = request.params.get('msg_signature', '')
        signature = request.params.get('signature', '')
        timestamp = request.params.get('timestamp', '')
        nonce = request.params.get('nonce', '')
        encrypt_type = request.params.get('encrypt_type', 'raw')

        try:
            check_signature(self.token, signature, timestamp, nonce)
        except InvalidSignatureException:
            return self.res_err(403)

        if request.httprequest.method == 'GET':
            return request.params.get('echostr', '')

        # POST
        msg = None
        if encrypt_type == 'raw':  # plaintext mode
            msg = parse_message(request.httprequest.data)
        else:  # encryption mode
            try:
                msg = self.crypto.decrypt_message(request.httprequest.data, msg_signature, timestamp, nonce)
            except (InvalidSignatureException, InvalidAppIdException):
                return self.res_err(403)
            msg = parse_message(msg)
        _logger.info('Receive message %s' % msg)

        ret = ''
        if msg.type in ['text', 'image', 'voice', 'video', 'location', 'link', 'shortvideo']:
            from .handlers.auto_reply import input_handle
            ret = input_handle(request, msg)
        elif msg.type == 'event':
            if msg.event == 'subscribe':
                ret = subscribe(request, msg)
            elif msg.event == 'unsubscribe':
                ret = unsubscribe(request, msg)
            elif msg.event == 'view':
                print('view event---------%s' % msg)
            elif msg.event == 'click':
                print('click event---------%s' % msg)
        elif msg.type == 'unknown':
            pass

        reply = create_reply(ret, msg).render()
        return reply if encrypt_type == 'raw' else self.crypto.encrypt_message(reply, nonce, timestamp)
