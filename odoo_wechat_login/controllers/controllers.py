# -*- coding: utf-8 -*-

import base64
import logging
import hashlib
import json
import simplejson
import requests
import werkzeug.utils
from odoo import http, fields
from datetime import datetime, timedelta
from odoo.http import request
from werkzeug.urls import url_encode
from werkzeug.exceptions import BadRequest

from odoo.exceptions import UserError, AccessDenied, ValidationError
from odoo.addons.auth_oauth.controllers.main import OAuthLogin as Home
from odoo.addons.auth_oauth.controllers.main import OAuthController as Controller

_logger = logging.getLogger(__name__)

# --- Constants ---
WECHAT_TOKEN_CACHE_KEY = 'wechat_access_token_{appid}'
WECHAT_TOKEN_EXPIRY_BUFFER = timedelta(minutes=10) # Refresh token 10 mins before expiry
MESSAGE_RATE_LIMIT_SECONDS = 60 # Min seconds between messages for the same user session

class WechatAuthController(http.Controller):
    """
    Controller handling WeChat Official Account (Service Account) OAuth login,
    user binding/creation, and message sending for Odoo.
    """

    # ==========================================================================
    # Helper Methods
    # ==========================================================================

    def _get_wechat_config(self):
        """ Safely retrieves WeChat AppID and Secret from Odoo parameters. """
        config = request.env['ir.config_parameter'].sudo()
        appid = config.get_param('odoo_wechat_login.appid')
        appsecret = config.get_param('odoo_wechat_login.appsecret')
        if not appid or not appsecret:
            _logger.error("WeChat AppID or AppSecret is not configured in Odoo settings.")
            # Raise configuration error instead of returning partial dict
            raise UserError("WeChat integration is not configured correctly. Please contact the administrator.")
        return {'appid': appid, 'secret': appsecret}

    def _error_response(self, message, log_level='error'):
        """ Logs an error and redirects to the standard /error page. """
        log_func = getattr(_logger, log_level, _logger.error)
        log_func(f"WeChat Auth Error: {message}")
        # Use werkzeug.urls.url_encode for robust parameter encoding
        error_param = werkzeug.urls.url_encode({'error_message': message})
        return request.redirect(f'/error?{error_param}')

    def _prepare_profile_vals(self, wechat_user_info, user_id, openid, form_wish):
        """ Prepares a dictionary of values for creating/updating wechat.user.profile. """
        return {
            'user_id': user_id,
            'openid': openid,
            'unionid': wechat_user_info.get('unionid'),
            'nickname': wechat_user_info.get('nickname'),
            'sex': str(wechat_user_info.get('sex', 0)), # Storing as string based on previous code
            'city': wechat_user_info.get('city', ''),
            'province': wechat_user_info.get('province', ''),
            'country': wechat_user_info.get('country', ''),
            'headimgurl': wechat_user_info.get('headimgurl', ''),
            'privilege': simplejson.dumps(wechat_user_info.get('privilege', [])),
            'raw_data': simplejson.dumps(wechat_user_info),
            'wish': form_wish,
            'last_update_time': fields.Datetime.now(), # Track last update
        }

    # ==========================================================================
    # WeChat API Interaction (Token Caching & Messaging)
    # ==========================================================================

    @classmethod
    def _fetch_new_wechat_token(cls, appid, appsecret):
        """ Fetches a new access token from WeChat API. """
        token_url = "https://api.weixin.qq.com/cgi-bin/token"
        params = {
            'grant_type': 'client_credential',
            'appid': appid,
            'secret': appsecret,
        }
        try:
            _logger.info(f"Requesting new WeChat access token for AppID: {appid[:4]}...")
            response = requests.get(token_url, params=params, timeout=10)
            response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
            data = response.json()
            if 'access_token' in data and 'expires_in' in data:
                _logger.info(f"Successfully fetched new WeChat access token for AppID: {appid[:4]}...")
                # Calculate expiry time (add a buffer)
                expires_at = datetime.now() + timedelta(seconds=data['expires_in'])
                return data['access_token'], expires_at
            else:
                _logger.error(f"Error fetching WeChat token: {data.get('errmsg', 'Unknown error')}")
                return None, None
        except requests.exceptions.RequestException as e:
            _logger.error(f"HTTP error fetching WeChat token: {e}")
            return None, None
        except Exception as e:
            _logger.exception("Unexpected error fetching WeChat token.")
            return None, None

    @classmethod
    def get_wechat_access_token(cls, appid, appsecret):
        """
        Retrieves WeChat access token, using cache first, fetching if needed.
        Uses ir.cache for simple caching. Consider a more persistent cache for multi-process Odoo.
        """
        cache = request.env['ir.cache'].sudo()
        cache_key = WECHAT_TOKEN_CACHE_KEY.format(appid=appid)
        cached_data = cache.get(cache_key) # Expected format: (token, expires_at_datetime)

        now = datetime.now()
        if cached_data:
            token, expires_at = cached_data
            # Check if token is still valid (considering buffer)
            if isinstance(expires_at, datetime) and expires_at - WECHAT_TOKEN_EXPIRY_BUFFER > now:
                 _logger.debug(f"Using cached WeChat access token for AppID: {appid[:4]}...")
                 return token
            else:
                 _logger.info(f"Cached WeChat token expired or invalid for AppID: {appid[:4]}...")

        # Fetch new token if cache missed or expired
        token, expires_at = cls._fetch_new_wechat_token(appid, appsecret)
        if token and expires_at:
            # Store the new token and its expiry time in cache
            cache.set(cache_key, (token, expires_at))
            return token
        else:
            # Failed to get a new token
            return None

    @classmethod
    def send_wechat_message(cls, openid, message, appid, appsecret):
        """
        Sends a text message using the Custom Service API.
        Uses cached access token.
        """
        access_token = cls.get_wechat_access_token(appid, appsecret)
        if not access_token:
            _logger.error(f"Cannot send message to {openid[:6]}...: Failed to get access token.")
            return False

        if not isinstance(message, str):
            message = str(message)

        payload = {
            "touser": openid,
            "msgtype": "text",
            "text": {"content": message}
        }
        send_url = f"https://api.weixin.qq.com/cgi-bin/message/custom/send?access_token={access_token}"
        headers = {'Content-Type': 'application/json; charset=utf-8'}

        try:
            _logger.info(f"Sending WeChat message to OpenID: {openid[:6]}...")
            resp = requests.post(
                send_url,
                data=simplejson.dumps(payload, ensure_ascii=False).encode('utf-8'),
                headers=headers,
                timeout=10
            )
            resp.raise_for_status()
            resp_data = resp.json()

            if resp_data.get('errcode') == 0:
                _logger.info(f"WeChat message sent successfully to OpenID: {openid[:6]}...")
                return True
            else:
                # Log specific WeChat error
                _logger.error(f"WeChat message sending failed | Code: {resp_data.get('errcode')} | Msg: {resp_data.get('errmsg', 'Unknown WeChat Error')} | OpenID: {openid[:6]}...")
                return False
        except requests.exceptions.Timeout:
             _logger.error(f"Timeout sending WeChat message to OpenID: {openid[:6]}...")
             return False
        except requests.exceptions.RequestException as req_err:
             _logger.error(f"HTTP error sending WeChat message to OpenID: {openid[:6]}... | Error: {req_err}")
             return False
        except Exception as e:
            _logger.exception(f"Unexpected error sending WeChat message to OpenID: {openid[:6]}...")
            return False

    # ==========================================================================
    # HTTP Routes
    # ==========================================================================

    @http.route('/wechat-verify', type='http', auth='public', methods=['GET'], csrf=False)
    def verify_wechat_token(self, **kwargs):
        """ Handles the initial WeChat server token verification. """
        # Consider getting the token from config instead of hardcoding
        # config_token = request.env['ir.config_parameter'].sudo().get_param('odoo_wechat_login.verify_token')
        config_token = "JIivg0Um8i0b6hGZ4bYQ3q" # Replace with config lookup if preferred
        signature = kwargs.get('signature', '')
        timestamp = kwargs.get('timestamp', '')
        nonce = kwargs.get('nonce', '')
        echostr = kwargs.get('echostr', '')

        if not all([config_token, signature, timestamp, nonce, echostr]):
             _logger.warning("WeChat verification request missing parameters.")
             return "Verification Failed: Missing Parameters"

        try:
            tmp_list = sorted([config_token, timestamp, nonce])
            tmp_str = ''.join(tmp_list).encode('utf-8')
            hash_str = hashlib.sha1(tmp_str).hexdigest()

            if hash_str == signature:
                _logger.info("WeChat Token verification successful.")
                return echostr # Must return echostr
            else:
                _logger.error(f"WeChat Token verification failed. Received: {signature}, Calculated: {hash_str}")
                return "Verification Failed"
        except Exception as e:
             _logger.exception("Error during WeChat token verification.")
             return "Verification Error"

    @http.route('/wechat/auth', type='http', auth='public', website=True)
    def start_wechat_auth(self, redirect=None, **kwargs):
        """ Redirects user to WeChat authorization page. """
        try:
            config = self._get_wechat_config() # Handles missing config error
            appid = config['appid']

            # ** ACTION: Generate and store CSRF state token **
            # csrf_token = odoo.tools.misc.generate_token()
            # request.session['wechat_oauth_state'] = csrf_token
            csrf_token = "dummy_state_token" # Replace with actual generation
            _logger.info(f"Generated WeChat OAuth state: {csrf_token}") # Log for debugging

            # Ensure redirect_uri is correctly URL-encoded
            base_url = request.env['ir.config_parameter'].sudo().get_param('web.base.url')
            redirect_uri = werkzeug.urls.url_join(base_url, '/wechat/callback')
            encoded_redirect_uri = werkzeug.urls.url_quote(redirect_uri)

            # Store intended redirect after successful login (optional)
            if redirect:
                request.session['wechat_oauth_redirect'] = redirect

            auth_url = (
                f"https://open.weixin.qq.com/connect/oauth2/authorize?"
                f"appid={appid}&"
                f"redirect_uri={encoded_redirect_uri}&"
                f"response_type=code&"
                f"scope=snsapi_userinfo&" # Scope to get user details
                f"state={csrf_token}"
                f"#wechat_redirect"
            )
            _logger.info(f"Redirecting user to WeChat auth URL for AppID: {appid[:4]}...")
            return request.redirect(auth_url, local=False)

        except UserError as e: # Catch configuration errors
            return self._error_response(str(e))
        except Exception as e:
            _logger.exception("Error initiating WeChat OAuth flow.")
            return self._error_response("Could not start WeChat authentication.")

    @http.route('/wechat/callback', type='http', auth='public', website=True, csrf=False)
    def handle_wechat_callback(self, code=None, state=None, **kwargs):
        """ Handles the callback from WeChat after user authorization. """
        _logger.info(f"Received WeChat callback - Code: {'yes' if code else 'no'}, State: {state}")

        # ** ACTION: Validate CSRF state token **
        # expected_state = request.session.get('wechat_oauth_state')
        # if not state or not expected_state or state != expected_state:
        #     _logger.error(f"Invalid OAuth state received. Expected: {expected_state}, Got: {state}")
        #     request.session.pop('wechat_oauth_state', None) # Clean up session
        #     return self._error_response("Invalid authentication request (State mismatch). Please try again.")
        # request.session.pop('wechat_oauth_state', None) # Valid state used, remove from session
        # _logger.info(f"OAuth state validation successful: {state}")

        if not code:
            error_desc = kwargs.get('error_description', 'Authorization denied by user or WeChat error.')
            return self._error_response(f"WeChat authorization failed: {error_desc}")

        try:
            config = self._get_wechat_config() # Handles missing config error
            appid = config['appid']
            secret = config['secret']

            # 1. Exchange code for access_token and openid
            token_url = "https://api.weixin.qq.com/sns/oauth2/access_token"
            params = {
                'appid': appid, 'secret': secret, 'code': code, 'grant_type': 'authorization_code'
            }
            _logger.info(f"Requesting WeChat OAuth token for AppID: {appid[:4]}...")
            token_resp = requests.get(token_url, params=params, timeout=10)
            token_resp.raise_for_status()
            token_data = token_resp.json()

            if 'errcode' in token_data:
                _logger.error(f"Error exchanging code for token: {token_data}")
                return self._error_response(f"WeChat authorization error (Code: {token_data.get('errcode')}).")

            access_token = token_data.get('access_token')
            openid = token_data.get('openid')
            if not access_token or not openid:
                 _logger.error(f"Missing access_token or openid in WeChat response: {token_data}")
                 return self._error_response("Failed to retrieve necessary credentials from WeChat.")

            _logger.info(f"OAuth token received for OpenID: {openid[:6]}...")

            # 2. Fetch user information
            user_info_url = "https://api.weixin.qq.com/sns/userinfo"
            params = {'access_token': access_token, 'openid': openid, 'lang': 'zh_CN'}
            _logger.info(f"Requesting WeChat user info for OpenID: {openid[:6]}...")
            user_resp = requests.get(user_info_url, params=params, timeout=10)
            user_resp.raise_for_status()
            user_data = user_resp.json()

            if 'errcode' in user_data:
                _logger.error(f"Error fetching user info: {user_data}")
                return self._error_response("Could not retrieve user profile from WeChat.")

            # Minimal logging of sensitive data
            _logger.info(f"User info received - Nickname: {user_data.get('nickname')}, UnionID: {'yes' if user_data.get('unionid') else 'no'}")

            # 3. Store essential info in session for the form/binding step
            # Only store necessary fields to avoid large session objects
            wechat_session_data = {
                'openid': user_data.get('openid'),
                'unionid': user_data.get('unionid'),
                'nickname': user_data.get('nickname'),
                'sex': user_data.get('sex'),
                'province': user_data.get('province'),
                'city': user_data.get('city'),
                'country': user_data.get('country'),
                'headimgurl': user_data.get('headimgurl'),
                'privilege': user_data.get('privilege'),
                # Do not store access_token in session long-term
            }
            request.session['wechat_user'] = wechat_session_data
            _logger.info(f"WeChat user info stored in session for OpenID: {openid[:6]}...")

            # 4. Redirect to the form page
            return request.redirect("/forms") # Redirect to your form page

        except UserError as e: # Catch configuration errors
            return self._error_response(str(e))
        except requests.exceptions.RequestException as e:
            _logger.error(f"HTTP error during WeChat callback processing: {e}")
            return self._error_response("Communication error with WeChat. Please try again.")
        except Exception as e:
            _logger.exception("Unexpected error during WeChat callback processing.")
            return self._error_response("An internal error occurred.")

    @http.route('/forms', type='http', auth='public', website=True)
    def display_form(self, **kwargs):
        """ Displays the form page, requires WeChat info in session. """
        wechat_user = request.session.get('wechat_user')
        if not wechat_user or not wechat_user.get('openid'):
            _logger.warning(f"Access attempt to /forms without WeChat session. IP: {request.httprequest.remote_addr}")
            # Redirect to start auth flow instead of just showing error
            return request.redirect('/wechat/auth')
            # return self._error_response("Please access this page via the WeChat menu or link.")

        _logger.info(f"Rendering form page for OpenID: {wechat_user.get('openid')[:6]}...")
        try:
            # Render your specific form template (e.g., 'website.alitec-forms')
            return request.render('website.alitec-forms', {
                'wechat_user': wechat_user,
                'hide_header_footer': True # Example parameter
            })
        except Exception as e:
            # Catch potential template rendering errors
            _logger.exception("Error rendering form template.")
            return self._error_response("Could not load the page. Please contact support.")

    @http.route('/forms/submit', type='http', auth='public', website=True, csrf=False)
    def handle_form_submission(self, **post_data):
        """
        Handles form submission, finds/binds/creates user, logs them in,
        and redirects to success page.
        """
        # 1. Verify WeChat session
        wechat_user_info = request.session.get('wechat_user')
        openid = wechat_user_info.get('openid') if wechat_user_info else None
        if not openid:
            _logger.error("Form submission attempt without WeChat OpenID in session.")
            return self._error_response("Your session has expired. Please re-authenticate via WeChat.")

        _logger.info(f"=== Form Submission Start - OpenID: {openid[:6]}... ===")

        # 2. Get and Validate Form Data
        form_phone = post_data.get('phone', '').strip()
        form_email = post_data.get('email', '').strip().lower() # Normalize email
        form_name = post_data.get('name', '').strip()
        form_wish = post_data.get('wish', '').strip()

        # Server-side validation is crucial
        errors = []
        if not form_phone or len(form_phone) < 8: # Basic length check
            errors.append("A valid phone number is required.")
        if not form_email or '@' not in form_email or '.' not in form_email:
            errors.append("A valid email address is required.")
        # Add other necessary validations (e.g., name required?)

        if errors:
            # Consider redirecting back to the form with errors displayed,
            # or use the generic error page.
            _logger.warning(f"Form validation failed for OpenID {openid[:6]}: {errors}")
            return self._error_response("Please correct the following errors: " + ", ".join(errors))

        _logger.info(f"Form data validated - Email: {form_email}, Phone: {form_phone}")

        try:
            config = self._get_wechat_config() # Get config for messaging
            env = request.env
            WechatUserProfile = env['wechat.user.profile'].sudo()
            ResUsers = env['res.users'].sudo()
            ResPartner = env['res.partner'].sudo()

            user_to_process = None
            outcome = None
            success_msg_content = "" # Content for the WeChat message

            # --- Logic Step 1: Check by OpenID via wechat.user.profile ---
            existing_profile = WechatUserProfile.search([('openid', '=', openid)], limit=1)

            if existing_profile and existing_profile.user_id:
                _logger.info(f"Found existing profile for OpenID {openid[:6]} linked to User ID: {existing_profile.user_id.id}. Outcome: existing.")
                user_to_process = existing_profile.user_id
                outcome = 'existing'
                success_msg_content = f"Welcome back, {user_to_process.name}! Your information is already registered."
                # Optional: Update profile data if changed
                try:
                    update_vals = self._prepare_profile_vals(wechat_user_info, user_to_process.id, openid, form_wish)
                    # Avoid overwriting user_id/openid
                    update_vals.pop('user_id', None)
                    update_vals.pop('openid', None)
                    existing_profile.write(update_vals)
                    _logger.info(f"Updated profile data for Profile ID: {existing_profile.id}")
                except Exception as e_update:
                    _logger.exception(f"Error updating profile ID {existing_profile.id}") # Log error but continue

            # --- Logic Step 2: Check by Email via res.users (if OpenID didn't match) ---
            elif not user_to_process:
                existing_user = ResUsers.search([('login', '=', form_email)], limit=1)

                if existing_user:
                    _logger.info(f"Found existing User ID: {existing_user.id} by email {form_email}. OpenID {openid[:6]} not yet linked. Binding now. Outcome: linked.")
                    user_to_process = existing_user
                    outcome = 'linked' # Use 'linked' for clarity

                    # Create the profile to bind WeChat
                    try:
                        profile_vals = self._prepare_profile_vals(wechat_user_info, user_to_process.id, openid, form_wish)
                        # Check if a profile exists for this user but different openid (unlikely here, but possible)
                        WechatUserProfile.create(profile_vals)
                        _logger.info(f"Created WeChat profile to link OpenID {openid[:6]} to User ID: {user_to_process.id}")
                        success_msg_content = f"Hello {user_to_process.name}! We've linked your WeChat account to your existing profile ({form_email})."
                    except Exception as e_bind:
                        _logger.exception(f"Failed to create wechat.user.profile for binding User ID {user_to_process.id} to OpenID {openid[:6]}.")
                        return self._error_response(f"Failed to link WeChat account. Error: {e_bind}")

            # --- Logic Step 3: Create New User (if neither OpenID nor Email matched) ---
            if not user_to_process:
                _logger.info(f"No existing profile/user found for OpenID {openid[:6]} / Email {form_email}. Creating new user. Outcome: new.")
                outcome = 'new'
                try:
                    # Ensure portal group exists
                    portal_group = env.ref('base.group_portal', raise_if_not_found=True)

                    # Create Partner first
                    partner_vals = {
                        'name': form_name or form_email, # Use email as fallback name
                        'email': form_email,
                        'phone': form_phone,
                        'is_company': False,
                        # Add other partner fields if needed
                    }
                    partner = ResPartner.create(partner_vals)
                    _logger.info(f"Created new Partner ID: {partner.id}")

                    # Create User linked to Partner
                    user_vals = {
                        'name': form_name or form_email,
                        'login': form_email,
                        'phone': form_phone, # Store phone on user as well?
                        'active': True,
                        'groups_id': [(6, 0, [portal_group.id])],
                        'partner_id': partner.id,
                        # ** SECURITY ACTION: Handle Password **
                        # Option 1: Use Odoo Signup (Recommended) - Requires auth_signup module
                        # 'action_id': env.ref('auth_signup.action_signup').id, # Example, needs setup
                        # Option 2: Set no password initially if WeChat is primary login
                        # Option 3: Generate secure random password (less user friendly)
                        # 'password': odoo.tools.misc.generate_password(),
                    }
                    # Use context to potentially bypass password reset email if using signup tokens
                    new_user = ResUsers.with_context(no_reset_password=True).create(user_vals)
                    user_to_process = new_user
                    _logger.info(f"Created new User ID: {user_to_process.id}")

                    # Create profile linked to New User
                    profile_vals = self._prepare_profile_vals(wechat_user_info, user_to_process.id, openid, form_wish)
                    WechatUserProfile.create(profile_vals)
                    _logger.info(f"Created WeChat profile for new User ID: {user_to_process.id}")

                    success_msg_content = (
                        "Registration Successful!\n"
                        f"Name: {user_to_process.name}\nEmail: {form_email}\nPhone: {form_phone}\n"
                        "Thank you for registering."
                    )
                except Exception as e_create:
                    _logger.exception("Error during new User/Partner/Profile creation.")
                    # Consider attempting cleanup (delete partner?) - complex
                    return self._error_response(f"Failed to create your profile. Error: {e_create}")

            # --- Post-processing: Login, Send Message, Redirect ---
            if user_to_process and outcome:
                # ** ACTION: Implement Odoo User Login **
                # This step is crucial for user experience but complex.
                # Requires careful handling of passwords or using OAuth session mechanisms.
                try:
                    # Example using password (IF a password was set securely)
                    # request.session.authenticate(request.env.cr.dbname, user_to_process.login, SECURE_PASSWORD_VARIABLE)

                    # Example using uid directly (less standard for web logins, use with caution)
                    # request.session.uid = user_to_process.id
                    # request.env['res.users'].browse(user_to_process.id)._update_last_login()

                    # Best approach might involve Odoo's auth_oauth helpers if applicable,
                    # or redirecting through a login flow that recognizes the session.
                    _logger.info(f"User {user_to_process.login} (ID: {user_to_process.id}) identified/created. Login step placeholder.")
                    # For now, we proceed without explicit login, relying on potential future logins.

                except Exception as auth_err:
                     _logger.error(f"Failed to authenticate user {user_to_process.login} after creation/binding: {auth_err}")
                     # Decide if this is critical - maybe redirect to login page?

                # Send WeChat Confirmation Message (with rate limiting)
                if success_msg_content:
                    last_sent_dt = request.session.get('last_wechat_msg_time')
                    now = datetime.now()
                    # Ensure last_sent_dt is a datetime object before comparison
                    allow_send = True
                    if isinstance(last_sent_dt, datetime):
                        if (now - last_sent_dt).total_seconds() < MESSAGE_RATE_LIMIT_SECONDS:
                            allow_send = False
                            _logger.warning(f"WeChat message sending skipped for OpenID {openid[:6]}... due to rate limit.")

                    if allow_send:
                        send_status = self.send_wechat_message(
                            openid, success_msg_content, config['appid'], config['secret']
                        )
                        if send_status:
                            # Store timestamp as datetime object in session
                            request.session['last_wechat_msg_time'] = now

                # Redirect to success page using f-string for clarity
                params = {
                    'outcome': outcome,
                    'user_name': user_to_process.name or 'User',
                    'phone': user_to_process.phone or ''
                }
                redirect_url = f'/success?{werkzeug.urls.url_encode(params)}'
                _logger.info(f"Redirecting to success page: {redirect_url}")
                # Clear the WeChat user info from session after successful processing
                request.session.pop('wechat_user', None)
                return request.redirect(redirect_url)
            else:
                # Fallback if logic somehow failed to set user or outcome
                _logger.error("Processing completed without determining user or outcome.")
                return self._error_response("An unexpected error occurred processing your information.")

        except UserError as e: # Catch configuration errors during processing
            return self._error_response(str(e))
        except ValidationError as e: # Catch Odoo validation errors
             _logger.warning(f"Validation error during form submission: {e}")
             return self._error_response(f"Invalid data: {e}")
        except Exception as e:
            _logger.exception("Unhandled exception in form submission handler.")
            return self._error_response("An unexpected system error occurred.")