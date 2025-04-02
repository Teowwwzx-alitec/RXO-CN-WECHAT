# -*- coding: utf-8 -*-

import base64
import logging
import hashlib
import json
import simplejson
import requests
import werkzeug.utils
from odoo import http
from datetime import datetime
from odoo.http import request
from werkzeug.urls import url_encode
from werkzeug.exceptions import BadRequest

from odoo.exceptions import AccessDenied, ValidationError
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as Home
from odoo.addons.auth_oauth.controllers.main import OAuthController as Controller

_logger = logging.getLogger(__name__)


class WechatAuthController(http.Controller):
    # --- Configuration Helper ---
    def _get_wechat_config(self):
        """ Gets WeChat AppID and Secret from Odoo system parameters """
        config = request.env['ir.config_parameter'].sudo()
        appid = config.get_param('odoo_wechat_login.appid')
        appsecret = config.get_param('odoo_wechat_login.appsecret')
        # Removed token as it wasn't used elsewhere in this logic
        # token = config.get_param('odoo_wechat_login.token')
        if not appid or not appsecret:
            _logger.error("WeChat AppID or AppSecret is missing in system parameters.")
            return None  # Return None to indicate missing config
        return {'appid': appid, 'secret': appsecret}

    # --- WeChat Server Verification Endpoint ---
    @http.route('/wechat-verify', type='http', auth='public', methods=['GET'], csrf=False)
    def verify_wechat_token(self, signature=None, timestamp=None, nonce=None, echostr=None, **kwargs):
        """ Handles the initial token verification from WeChat server """
        # Fetch the verification token securely (replace hardcoded value)
        token = request.env['ir.config_parameter'].sudo().get_param('odoo_wechat_login.token',
                                                                    "DEFAULT_FALLBACK_TOKEN")  # Example fallback
        if not token:
            _logger.error("WeChat verification token is not set in system parameters.")
            return "Configuration Error"

        try:
            tmp_list = sorted([token, timestamp or '', nonce or ''])
            tmp_str = ''.join(tmp_list).encode('utf-8')
            hash_str = hashlib.sha1(tmp_str).hexdigest()

            if hash_str == signature:
                _logger.info("✅ WeChat Token verification successful.")
                return echostr or ''  # Return echostr as required by WeChat
            else:
                _logger.error(f"❌ Token verification failed | Received: {signature} | Calculated: {hash_str}")
                return "Verification Failed"
        except Exception as e:
            _logger.exception("Error during WeChat token verification.")
            return "Verification Error"

    # --- WeChat OAuth Callback Handler ---
    @http.route('/form', type='http', auth='public', website=True, csrf=False)  # Consider csrf=True if possible
    def handle_wechat_auth(self, code=None, state=None, **kwargs):
        """ Handles the redirect back from WeChat after user authorization """
        try:
            _logger.info(f"=== WeChat OAuth Callback Start - Code: {'yes' if code else 'no'}, State: {state} ===")

            # ** ACTION: Implement State Validation **
            # 1. Generate unique state before redirecting user TO WeChat, store in session.
            # 2. Compare received 'state' param with session value. Abort if mismatch (CSRF).
            # saved_state = request.session.pop('oauth_state', None)
            # if not state or not saved_state or state != saved_state:
            #     _logger.warning("OAuth state validation failed. Possible CSRF attempt.")
            #     return self._error_response("Authorization failed (Invalid State). Please try again.")

            if not code:
                _logger.error("Authorization failed: 'code' parameter is missing from WeChat callback.")
                return self._error_response("Authorization failed: Missing required parameter.")

            config = self._get_wechat_config()
            if not config:
                return self._error_response("System configuration error (WeChat credentials missing).")

            # 1. Exchange code for access_token and openid
            token_url = (
                f"https://api.weixin.qq.com/sns/oauth2/access_token?"
                f"appid={config['appid']}&secret={config['secret']}&"
                f"code={code}&grant_type=authorization_code"
            )
            _logger.info(f"Requesting OAuth token...")
            token_resp = requests.get(token_url, timeout=10)
            token_resp.raise_for_status()  # Raise HTTP errors
            token_data = token_resp.json()

            if token_data.get('errcode'):
                _logger.error(f"Failed to get OAuth token: {token_data}")
                return self._error_response(f"WeChat authorization failed (Code: {token_data.get('errcode')}).")

            access_token = token_data.get('access_token')
            openid = token_data.get('openid')
            if not access_token or not openid:
                _logger.error(f"OAuth token response missing access_token or openid: {token_data}")
                return self._error_response("Failed to retrieve necessary WeChat credentials.")

            # 2. Fetch user info using the access_token
            user_info_url = (
                f"https://api.weixin.qq.com/sns/userinfo?"
                f"access_token={access_token}&openid={openid}&lang=zh_CN"
            )
            _logger.info(f"Requesting user info for OpenID: {openid[:6]}...")
            user_resp = requests.get(user_info_url, timeout=10)
            user_resp.raise_for_status()  # Raise HTTP errors
            # Decode explicitly for correct character handling
            user_data = simplejson.loads(user_resp.content.decode('utf-8'))

            if user_data.get('errcode'):
                _logger.error(f"Failed to get user info: {user_data}")
                return self._error_response("Failed to retrieve user information from WeChat.")

            # 3. Prepare and store user data in session
            wechat_user = {
                'openid': user_data.get('openid'),
                'unionid': user_data.get('unionid'),  # Store unionid if available
                'nickname': user_data.get('nickname'),
                'sex': user_data.get('sex'),
                'province': user_data.get('province'),
                'city': user_data.get('city'),
                'country': user_data.get('country'),
                'headimgurl': user_data.get('headimgurl'),
                'privilege': user_data.get('privilege', [])  # Ensure default is list
            }
            _logger.info(
                f"User info received: Nickname='{wechat_user['nickname']}', OpenID={wechat_user['openid'][:6]}...")

            request.session['wechat_user'] = wechat_user
            _logger.info("WeChat user data stored in session.")
            return self._redirect_to_form()  # Redirect to the form page

        except requests.exceptions.Timeout:
            _logger.error("Request to WeChat API timed out during OAuth flow.")
            return self._error_response("WeChat server timed out. Please try again later.")
        except requests.exceptions.RequestException as e:
            _logger.error(f"Network error during WeChat OAuth flow: {e}")
            return self._error_response("Network error communicating with WeChat. Please try again.")
        except Exception as e:
            _logger.exception("Unexpected error during WeChat authorization callback.")
            return self._error_response(f"An unexpected system error occurred: {str(e)}")

    # --- Redirect Helper ---
    def _redirect_to_form(self):
        """ Redirects user to the data entry form page """
        if not request.session.get('wechat_user'):
            # This case should ideally not happen if session is managed correctly
            _logger.warning("Attempted redirect to form, but session data missing.")
            return self._error_response("Session information lost. Please start the process again.")
        return request.redirect("/forms")

    # --- Error Response Helper ---
    def _error_response(self, message="An unexpected error occurred."):
        """ Redirects to the generic /error page with a message """
        _logger.error(f"Error response triggered: {message}")
        try:
            # Ensure message is a string
            message_str = str(message)
            error_param = werkzeug.utils.url_quote(message_str)
            return request.redirect(f'/error?error_message={error_param}')
        except Exception as e_redir:
            _logger.exception("Failed to redirect to error page.")
            # Fallback plain text response if redirect fails
            return werkzeug.wrappers.Response(f"System Error: {message}", status=500, content_type='text/plain')

    # --- Form Display Endpoint ---
    @http.route('/forms', type='http', auth='public', website=True)
    def display_form(self, **kwargs):
        """ Displays the user data entry form """
        wechat_user = request.session.get('wechat_user')

        if not wechat_user or not wechat_user.get('openid'):
            _logger.warning("Unauthorized access attempt to /forms page. IP: %s", request.httprequest.remote_addr)
            # Redirect to an info page or error instead of showing form
            return self._error_response("Please access this page through the WeChat authorization link.")

        _logger.info("Rendering form page for OpenID: %s", wechat_user.get('openid')[:6])

        try:
            # Render your specific form template (e.g., 'website.alitec-forms')
            return request.render('website.alitec-forms', {  # MAKE SURE 'website.alitec-forms' IS CORRECT
                'wechat_user': wechat_user,
                'hide_header_footer': True  # Optional: if your template uses this
            })
        except Exception as e:  # Catch potential rendering errors
            _logger.exception("Failed to render the form template.")
            return self._error_response("Error loading the page. Please contact support.")

    # --- Form Submission Handler (Refined Logic) ---
    @http.route('/forms/submit', type='http', auth='public', website=True, csrf=False)  # Consider csrf=True
    def handle_form_submission(self, **post_data):
        """ Handles form submission, finds/creates/binds user, and redirects. """
        try:
            # 1) Get WeChat info from session
            wechat_user = request.session.get('wechat_user', {})
            openid = wechat_user.get('openid')
            if not openid:
                _logger.error("Session missing WeChat OpenID during form submission.")
                return self._error_response("Session information lost. Please re-authorize via WeChat.")

            _logger.info(f"=== Form Submission Start - OpenID: {openid[:6]}... ===")

            # 2) Get and Validate Form Data
            phone = post_data.get('phone', '').strip()
            email = post_data.get('email', '').strip().lower()  # Normalize email
            name = post_data.get('name', '').strip()  # Get name, use later if needed
            wish = post_data.get('wish', '').strip()  # Get optional wish field

            # Basic Validations (Add more as needed)
            if not phone or len(phone) < 8:  # Basic phone check
                return self._error_response("A valid phone number is required.")
            if not email or '@' not in email or '.' not in email:  # Basic email check
                return self._error_response("A valid email address is required.")
            _logger.info(f"Form data validated - Email: {email}, Phone: {phone}")

            config = self._get_wechat_config()
            if not config:  # Check config needed for message sending
                return self._error_response("System configuration error (WeChat credentials missing).")

            user_to_process = None
            outcome = None
            success_msg = ""

            # --- Logic Step 1: Check by OpenID via wechat.user.profile ---
            existing_profile = request.env['wechat.user.profile'].sudo().search([
                ('openid', '=', openid)
            ], limit=1)

            if existing_profile and existing_profile.user_id:
                _logger.info(
                    f"Found existing profile for OpenID {openid[:6]} linked to User ID: {existing_profile.user_id.id}. Outcome: existing.")
                user_to_process = existing_profile.user_id
                outcome = 'existing'
                success_msg = f"Welcome back, {user_to_process.name}! Your information is already registered."
                # Optional: Update profile data if changed?
                # existing_profile.sudo().write({'nickname': wechat_user.get('nickname'), ...})

            # --- Logic Step 2: Check by Email via res.users (if OpenID didn't match) ---
            elif not user_to_process:  # Only proceed if step 1 didn't find a user
                existing_user = request.env['res.users'].sudo().search([
                    ('login', '=', email)  # Use normalized email
                ], limit=1)

                if existing_user:
                    _logger.info(
                        f"Found existing User ID: {existing_user.id} by email {email}. OpenID {openid[:6]} not yet linked. Binding now. Outcome: existing.")
                    user_to_process = existing_user
                    outcome = 'existing'  # Or 'linked' if you prefer

                    # ** CRITICAL ACTION: Create the profile to bind WeChat **
                    try:
                        profile_vals = self._prepare_profile_vals(wechat_user, user_to_process.id, openid, wish)
                        # Check if profile ALREADY exists for this user_id but different openid (unlikely but possible)
                        existing_profile_for_user = request.env['wechat.user.profile'].sudo().search(
                            [('user_id', '=', user_to_process.id)], limit=1)
                        if not existing_profile_for_user:
                            new_profile = request.env['wechat.user.profile'].sudo().create(profile_vals)
                            _logger.info(
                                f"Created WeChat profile (ID: {new_profile.id}) to link OpenID {openid[:6]} to User ID: {user_to_process.id}")
                        else:
                            _logger.warning(
                                f"User ID {user_to_process.id} already has a WeChat profile (ID: {existing_profile_for_user.id}). Not creating a new one for OpenID {openid[:6]}. Check for potential issues.")
                            # Decide how to handle this: update existing? error? ignore? For now, we proceed.

                        success_msg = f"Hello {user_to_process.name}! We've linked your WeChat account to your existing profile."
                    except Exception as e_bind:
                        _logger.exception(
                            f"Failed to create/link wechat.user.profile for User ID {user_to_process.id} / OpenID {openid[:6]}.")
                        return self._error_response(f"Failed to link WeChat account: {str(e_bind)}")

            # --- Logic Step 3: Create New User (if neither OpenID nor Email matched) ---
            if not user_to_process:
                _logger.info(
                    f"No existing profile/user found for OpenID {openid[:6]} or Email {email}. Creating new user. Outcome: new.")
                outcome = 'new'
                try:
                    # Ensure Portal group exists
                    portal_group = request.env.ref('base.group_portal', raise_if_not_found=False)
                    if not portal_group:
                        _logger.error("Portal user group ('base.group_portal') not found.")
                        return self._error_response("System configuration error (User Group Missing).")

                    # Create Partner first (best practice)
                    partner_vals = {'name': name or email, 'email': email, 'phone': phone, 'is_company': False}
                    partner = request.env['res.partner'].sudo().create(partner_vals)

                    # Create User linked to Partner
                    user_vals = {
                        'name': name or email, 'login': email, 'phone': phone, 'active': True,
                        'groups_id': [(6, 0, [portal_group.id])], 'partner_id': partner.id
                        # ** ACTION: Handle password securely (e.g., using auth_signup flow, random password, or no password if portal only) **
                        # 'password': 'SECURE_PASSWORD_OR_REMOVE',
                    }
                    # Use context to potentially avoid password reset emails if using signup tokens later
                    new_user = request.env['res.users'].with_context(no_reset_password=True).sudo().create(user_vals)
                    user_to_process = new_user
                    _logger.info(f"Created new User ID: {user_to_process.id} / Partner ID: {partner.id}")

                    # Create Profile linked to New User
                    profile_vals = self._prepare_profile_vals(wechat_user, user_to_process.id, openid, wish)
                    new_profile = request.env['wechat.user.profile'].sudo().create(profile_vals)
                    _logger.info(f"Created WeChat profile (ID: {new_profile.id}) for new User ID: {user_to_process.id}")

                    success_msg = (
                        "Registration Successful!\n"
                        f"Name: {user_to_process.name}\nEmail: {email}\nPhone: {phone}\n"
                        "Thank you for submitting your information."
                    )
                except Exception as e_create:
                    _logger.exception("Error during new User/Partner/Profile creation.")
                    # Consider cleanup of created partner if user/profile fails (more complex)
                    return self._error_response(f"Failed to create user profile: {str(e_create)}")

            # --- Post-processing: Login, Send Message, Redirect ---
            if user_to_process and outcome:
                # ** ACTION: Implement Odoo Login for user_to_process **
                # This part is crucial for user experience but depends heavily on your Odoo setup
                # (auth_oauth helpers, password handling, session management).
                # Example using session authenticate (requires password or alternative auth):
                # try:
                #     request.session.authenticate(request.env.cr.dbname, user_to_process.login, 'PASSWORD_PLACEHOLDER')
                #     _logger.info(f"User {user_to_process.login} authenticated successfully into Odoo session.")
                # except Exception as auth_err:
                #     _logger.error(f"Failed to authenticate user {user_to_process.login} after creation/binding: {auth_err}")
                #     # Decide if this is critical - maybe redirect anyway?

                # Send WeChat Confirmation Message (with rate limiting)
                if success_msg:  # Only send if a message was prepared
                    last_sent_dt = request.session.get('last_wechat_msg_time')
                    # Ensure last_sent is datetime before comparison
                    can_send = True
                    if isinstance(last_sent_dt, datetime):
                        if (datetime.now() - last_sent_dt).total_seconds() < 60:  # 60 second cooldown
                            can_send = False
                            _logger.warning(
                                f"WeChat message sending skipped for OpenID {openid[:6]}... due to rate limit.")

                    if can_send:
                        # Use static method call
                        send_status = WechatAuthController.send_wechat_message(openid, success_msg, config['appid'],
                                                                               config['secret'])
                        if send_status:
                            request.session['last_wechat_msg_time'] = datetime.now()  # Store datetime object
                        else:
                            _logger.error(f"Failed to send WeChat confirmation for OpenID {openid[:6]}...")
                            # Non-critical usually, proceed with redirect

                # Redirect to success page
                redirect_url = '/success?outcome=%s&user_name=%s&phone=%s' % (
                    outcome,
                    werkzeug.utils.url_quote(user_to_process.name or 'User'),  # Ensure name exists
                    werkzeug.utils.url_quote(user_to_process.phone or '')  # Ensure phone exists
                )
                _logger.info(f"Processing complete for OpenID {openid[:6]}. Redirecting to: {redirect_url}")
                return request.redirect(redirect_url)
            else:
                # Fallback error if logic failed to determine user/outcome
                _logger.error("Form processing completed without determining user or outcome. OpenID: %s", openid[:6])
                return self._error_response("An unexpected error occurred while processing your information.")

        except Exception as e:
            _logger.exception("Unhandled exception in form submission handler.")
            return self._error_response(f"An unexpected system error occurred: {str(e)}")

    # --- Helper to prepare profile data ---
    def _prepare_profile_vals(self, wechat_user_session_data, user_id, openid, wish):
        """ Helper to prepare values dictionary for wechat.user.profile creation/update """
        return {
            'user_id': user_id,
            'openid': openid,
            'unionid': wechat_user_session_data.get('unionid'),  # Store unionid if available
            'nickname': wechat_user_session_data.get('nickname'),
            'sex': str(wechat_user_session_data.get('sex', 0)),  # Store as string if model field is Char
            'city': wechat_user_session_data.get('city', ''),
            'province': wechat_user_session_data.get('province', ''),
            'country': wechat_user_session_data.get('country', ''),
            'headimgurl': wechat_user_session_data.get('headimgurl', ''),
            # Store complex types as JSON strings if model fields are Text/Char
            'privilege': simplejson.dumps(wechat_user_session_data.get('privilege', [])),
            'raw_data': simplejson.dumps(wechat_user_session_data),  # Store all raw data
            'wish': wish,  # Store the wish from the form
        }

    # --- WeChat Message Sending (Static Method) ---
    @staticmethod
    def send_wechat_message(openid, message, appid, appsecret):
        """
        Sends a text message using WeChat Custom Service API.
        ** URGENT ACTION: Implement Access Token Caching **
        Fetching a token on every call WILL hit rate limits quickly.
        """
        # >>> PLACEHOLDER for Access Token Caching Logic <<<
        # 1. Try get cached token for appid (e.g., from ir.cache, custom model, file)
        # 2. If valid token exists, use it.
        # 3. If not valid/expired: Fetch new token using client_credential grant:
        #    token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
        #    Check response, store token + expiry time (usually 7200s).
        # 4. If token fetch fails, return False.
        # 5. Use the obtained access_token below.

        # --- Mock Fetching (REPLACE WITH CACHING) ---
        try:
            _logger.info(f"Fetching NEW WeChat access_token for sending message (AppID: {appid})... CACHING NEEDED!")
            token_url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={appsecret}"
            token_resp = requests.get(token_url, timeout=5)
            token_resp.raise_for_status()
            token_data = token_resp.json()
            access_token = token_data.get('access_token')
            if not access_token:
                _logger.error("Failed to get WeChat Access Token for sending message: %s",
                              token_data.get('errmsg', 'No error message'))
                return False
        except requests.exceptions.RequestException as token_err:
            _logger.error(f"Error fetching WeChat access token: {token_err}")
            return False
        # --- End Mock Fetching ---

        try:
            # Ensure message is string
            message_content = str(message)

            payload = {
                "touser": openid,
                "msgtype": "text",
                "text": {"content": message_content}
            }
            send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"
            headers = {'Content-Type': 'application/json; charset=utf-8'}

            _logger.info(f"Sending WeChat message to OpenID: {openid[:6]}...")
            resp = requests.post(
                send_url,
                data=simplejson.dumps(payload, ensure_ascii=False).encode('utf-8'),
                headers=headers,
                timeout=10  # Longer timeout for sending
            )
            resp.raise_for_status()  # Check for HTTP errors
            resp_data = resp.json()

            if resp_data.get('errcode') == 0:
                _logger.info(f"WeChat message sent successfully to OpenID: {openid[:6]}.")
                return True
            else:
                # Log specific WeChat errors
                _logger.error("Failed to send WeChat message. Error Code: %s, Message: %s, OpenID: %s",
                              resp_data.get('errcode'), resp_data.get('errmsg', 'Unknown WeChat Error'), openid[:6])
                return False

        except requests.exceptions.Timeout:
            _logger.error(f"WeChat API request timed out while sending message to OpenID: {openid[:6]}.")
            return False
        except requests.exceptions.RequestException as req_err:
            _logger.error(f"WeChat API request error while sending message to OpenID {openid[:6]}: {req_err}")
            return False
        except Exception as e:
            _logger.exception(f"Unexpected error sending WeChat message to OpenID: {openid[:6]}.")
            return False