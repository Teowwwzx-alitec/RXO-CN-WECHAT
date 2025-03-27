from odoo import fields, models


class WechatUserProfile(models.Model):
    _name = 'wechat.user.profile'
    _description = '微信用户扩展档案'

    user_id = fields.Many2one('res.users', '系统用户', required=True)
    nickname = fields.Char('微信昵称')
    sex = fields.Selection(
        [('0','未知'), ('1','男'), ('2','女')],
        '性别'
    )
    city = fields.Char('城市')
    province = fields.Char('省份')
    headimgurl = fields.Char('头像URL')
    privilege = fields.Text('特权信息')
    raw_data = fields.Text('原始数据')