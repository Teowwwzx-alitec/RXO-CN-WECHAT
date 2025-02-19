import asyncio
import threading
import time
import datetime

from odoo.addons.odooer_wechat.common import client_instance,WxClient
from odoo import models, fields, api, SUPERUSER_ID
from ..common import wx_entry

def get_now_time_str():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

class WxUser(models.Model):
    _name = 'wx.user'
    _description='公众号微信用户'

    subscribe = fields.Boolean('是否订阅')
    openid = fields.Char('公众号 openid', required=True, help='用户的标识，对当前公众号唯一')
    subscribe_time = fields.Datetime('关注时间', help='用户关注时间，如果用户曾多次关注，则取最后关注时间')
    unionid = fields.Char('unionid', index=True, help='只有在用户将公众号绑定到微信开放平台帐号后，才会出现该字段。')
    remark = fields.Char('备注', help='公众号运营者对粉丝的备注，公众号运营者可在微信公众平台用户管理界面对粉丝添加备注')
    groupid = fields.Char('分组ID', help='用户所在的分组ID（兼容旧的用户分组接口）')
    tagid_list = fields.Char('标签ID', help='用户被打上的标签ID列表')
    subscribe_scene = fields.Char('渠道来源', help='返回用户关注的渠道来源，ADD_SCENE_SEARCH 公众号搜索，ADD_SCENE_ACCOUNT_MIGRATION 公众号迁移，ADD_SCENE_PROFILE_CARD 名片分享，ADD_SCENE_QR_CODE 扫描二维码)')
    qr_scene = fields.Char('扫码场景', help='二维码扫码场景（开发者自定义）')
    qr_scene_str = fields.Char('扫码场景描述', help='二维码扫码场景描述（开发者自定义）')
    active = fields.Boolean('启用', default=True)

    @api.model
    def is_follower(self, unionid):
        user = self.search([('unionid', '=', unionid)])
        return len(user) == 1 and user.subscribe
    
    def action_sync_user(self):
        '''同步当前用户'''
        self.ensure_one()
        wx_appid, wx_secret = self.get_wx_config()
        wx_client = client_instance(wx_appid, wx_secret)
        loop = wx_client.loop
        info = loop.run_until_complete(self.async_get_user_info(self.openid, wx_client))
        if not info:
            return
        follower = self.search([('unionid', '=', info.unionid)])
        if follower:
            follower.write(info.get_values())

    @api.model
    def get_wx_config(self):
        '''公众号配置'''
        config = self.env['wx.config'].sudo().get_cur()
        return config.wx_appid, config.wx_secret

    @api.model
    def action_sync_users(self):
        self.env['bus.bus']._sendone(self.env.user.partner_id, 'simple_notification', {
            'title': '同步关注用户信息',
            'message': '开始同步公众号关注者信息',
            'warning': True
        })

        wx_appid, wx_secret = self.get_wx_config()
        wx_client = client_instance(wx_appid, wx_secret)
        
        # create a threading to avoid odoo ui blocking
        def _sync():
            loop = wx_client.loop
            loop.run_until_complete(self.sync_users(wx_client))

        thread = threading.Thread(target=_sync)
        thread.start()

    async def sync_users(self, wx_client):
        start = time.time()
        uid = self.env.uid
        is_success = True
        with self.env.registry.cursor() as new_cr:
            self.env = api.Environment(new_cr, uid, {})
            print(f'start sync at {get_now_time_str()}......')
            try:
                await self.async_Get_followers(wx_client)
                admin_user = self.env['ir.config_parameter'].sudo().get_param('wechat_admin_openid')
                await wx_client.post_sys_message(admin_user, '同步用户信息成功')
                print('\nsync success!')
            except Exception as e:
                is_success = False
                print('sync failed, error: \n')
            finally:
                print(f'\nsync end at {get_now_time_str()}, cost {round(time.time() - start, 2)}s')
                self.env['bus.bus']._sendone(self.env.user.partner_id, 'simple_notification', {
                    'title': '同步关注用户信息',
                    'message': f'同步关注公众号用户信息结束, {"success" if is_success else "failed"}',
                    'warning': True if is_success else False
                })

    async def async_get_user_info(self, openid, wx_client):
        info = await wx_client.get_user_info(openid)
        if not info:
            follower = self.search([('openid', '=', openid)])
            if follower:
                follower.write({'subscribe': False})
            return
        follower = self.search([('openid', '=', openid)])
        if not follower:
            self.create(info.get_values())
        else:
            follower.with_context(sync=True).write(info.get_values())

    async def async_Get_followers(self, wx_client):
        # 获取关注者列表
        followers = await wx_client.get_followers()
        if not followers:
            self.search([]).write({'subscribe': False})
            return
        tasks = []
        for openid in followers.data['openid']:
            tasks.append(self.async_get_user_info(openid, wx_client))
        # 获取所有关注用户信息
        await asyncio.gather(*tasks)

    def on_follow_event(self, user):
        pass
        # self.sudo().create({
        #     'company_id': company.id,
        #     'name': f'we_id_{we_id}',
        #     'we_id': we_id,
        #     'parent_id': parent_dep.id,
        #     'we_parent_id': we_parent_id,
        #     'manager_id': False
        # })

    def on_unfollow_event(self, user):
        user = self.sudo().search([('unionid', '=', user.unionid)])
        if user:
            user.unlink()

    def post_order_message(self, order_no, product, price, appid, pagepath):
        self.ensure_one()
        if not self.subscribe:
            return
        wx_appid, wx_secret = self.get_wx_config()
        wx_client = client_instance(wx_appid, wx_secret)
        entry = wx_entry.wxenv(self.env) # 解决两个库 token 重复获取问题
        token = entry.client.access_token
        loop = wx_client.loop
        task = loop.create_task(wx_client.post_order_message(token, self.openid, order_no, product, price, appid, pagepath))
        loop.run_until_complete(task)

    @api.model
    def post_order_sys_message(self, order_no, product, price, phone):
        wx_appid, wx_secret = self.get_wx_config()
        wx_client = client_instance(wx_appid, wx_secret)
        admin_user = self.env['ir.config_parameter'].sudo().get_param('wechat_admin_openid')
        entry = wx_entry.wxenv(self.env) # 解决两个库 token 重复获取问题
        token = entry.client.access_token
        loop = wx_client.loop
        task = loop.create_task(wx_client.post_order_sys_message(token, admin_user, order_no, product, price, phone))
        loop.run_until_complete(task)

    def post_message(self, message):
        '''批量推送消息'''
        tasks = []
        wx_appid, wx_secret = self.get_wx_config()
        wx_client = WxClient(wx_appid, wx_secret) # 3.重新生成 client
        for follower in self:
            if follower.subscribe:
                tasks.append(wx_client.post_sys_message(follower.openid, message))
        loop = wx_client.loop 
        loop.run_until_complete(asyncio.gather(*tasks))
        loop.run_until_complete(wx_client.close())
        loop.close()

    def sync_remark(self):
        '''批量更新备注'''
        print(threading.current_thread())
        tasks = []
        wx_appid, wx_secret = self.get_wx_config()
        wx_client = WxClient(wx_appid, wx_secret) # 3.重新生成 client
        for follower in self:
            if follower.subscribe:
                tasks.append(wx_client.update_remark(follower.openid, follower.remark))
        # 1. 直接使用run_until_complete报错：There is no current event loop in thread。可能是 write 线程比较特殊？
        # 2. 新建 loop 会与 session 冲突，报错：Timeout context manager should be used inside a task.
        # loop =  asyncio.new_event_loop() 
        # asyncio.set_event_loop(loop)
        loop = wx_client.loop 
        loop.run_until_complete(asyncio.gather(*tasks))
        loop.run_until_complete(wx_client.close())
        loop.close()


    def write(self, vals):
        res = super().write(vals)
        if 'remark' in vals and not self._context.get('sync'):
            self.sync_remark()
        return res