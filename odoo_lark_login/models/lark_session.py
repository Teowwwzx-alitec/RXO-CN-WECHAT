# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from odoo import api, fields, models


class LarkUserSession(models.Model):
    _name = "lark.user.session"
    _description = "Lark User Session"
    _rec_name = "user_id"

    user_id = fields.Many2one("res.users", string="User", required=True, ondelete="cascade", index=True)
    token = fields.Char(string="Access Token", required=True)
    create_date = fields.Datetime(string="Created", readonly=True)
    expire_date = fields.Datetime(string="Expires", compute="_compute_expire_date", store=True)
    last_used = fields.Datetime(string="Last Used", default=fields.Datetime.now)
    active = fields.Boolean(string="Active", default=True)
    
    @api.depends("create_date", "token")
    def _compute_expire_date(self):
        """Set expiration date based on token lifetime (default 7200 seconds)"""
        for record in self:
            if record.create_date:
                record.expire_date = record.create_date + timedelta(seconds=7200)  # Default Lark token lifetime
            else:
                record.expire_date = fields.Datetime.now() + timedelta(seconds=7200)
    
    @api.model
    def cleanup_expired_sessions(self):
        """Cleanup expired tokens"""
        expired = self.search([
            ("expire_date", "<", fields.Datetime.now()),
            ("active", "=", True)
        ])
        if expired:
            expired.write({"active": False})
        return True
    
    @api.model
    def find_valid_token(self, user_id):
        """Find a valid token for the given user"""
        valid_session = self.search([
            ("user_id", "=", user_id),
            ("expire_date", ">", fields.Datetime.now()),
            ("active", "=", True),
        ], limit=1, order="create_date DESC")
        
        if valid_session:
            valid_session.write({"last_used": fields.Datetime.now()})
            return valid_session.token
        return False
    
    @api.model
    def create_or_update_session(self, user_id, token):
        """Create a new session or update existing"""
        self.create({
            "user_id": user_id,
            "token": token
        })
        return True
