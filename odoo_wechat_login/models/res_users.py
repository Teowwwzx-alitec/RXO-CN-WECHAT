# -*- coding: utf-8 -*-

import logging
import requests
import simplejson

from werkzeug.urls import url_encode
from odoo import _, api, fields, models
from werkzeug.exceptions import BadRequest
from odoo.exceptions import AccessDenied, ValidationError


_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _inherit = "res.users"
