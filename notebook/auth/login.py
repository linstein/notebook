"""Tornado handlers for logging into the notebook."""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.

import functools
import re
import os
import urllib
import warnings
from typing import cast
from urllib.parse import urlparse
import tornado.auth
import tornado.web
import tornado

import uuid

import urllib.parse as urllib_parse
from tornado import escape, httpclient
from tornado.concurrent import future_set_result_unless_cancelled, Future, future_set_exc_info
from tornado.escape import url_escape
from tornado.log import gen_log
from tornado.util import ArgReplacer

from .security import passwd_check, set_password
from tornado.web import RequestHandler
from ..base.handlers import IPythonHandler
import typing



class KeycloakOAuth2Mixin(tornado.auth.OAuth2Mixin):
    _OAUTH_AUTHORIZE_URL = "http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/auth"
    _OAUTH_ACCESS_TOKEN_URL = "http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/token"
    _OAUTH_USERINFO_URL = "http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/userinfo"
    _OAUTH_NO_CALLBACKS = False
    _OAUTH_SETTINGS_KEY = 'keycloak'
    _CLIENTID = 'client2'
    _CLIENTSECRET = '3c1219f6-89a0-4d35-989b-5fae3cd80d79'
    cookie_name='_user_id'

    async def get_authenticated_user(self, redirect_uri, code):
        handler = cast(RequestHandler, self)
        http = httpclient.AsyncHTTPClient()
        body = urllib_parse.urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": 'client2',
            "client_secret":'3c1219f6-89a0-4d35-989b-5fae3cd80d79',
            "grant_type": "authorization_code",
        })

        response =await http.fetch(
            "http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/token",
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body,
        )
        return escape.json_decode(response.body)
        # fut.add_done_callback(wrap(functools.partial(self._on_access_token, callback)))


#登录处理函数
class LoginHandler(IPythonHandler,KeycloakOAuth2Mixin):
    #登录页面跳转到keycloak的登录认证页面，登录成功设置cookie
    def redirect_keycloak(self):
        keycloak_url="http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/auth?client_id=client2&redirect_uri=http%3A%2F%2F39.97.126.112%3A8988%2Flab&scope=openid+email&access_type=offline&response_type=code"
        self.redirect(keycloak_url)

    #登录后重定向到lab页面
    def _redirect_safe(self, url, default=None):
        """Redirect if url is on our PATH

        Full-domain redirects are allowed if they pass our CORS origin checks.

        Otherwise use default (self.base_url if unspecified).
        """
        if default is None:
            default = self.base_url
        # protect chrome users from mishandling unescaped backslashes.
        # \ is not valid in urls, but some browsers treat it as /
        # instead of %5C, causing `\\` to behave as `//`
        url = url.replace("\\", "%5C")
        parsed = urlparse(url)
        if parsed.netloc or not (parsed.path + '/').startswith(self.base_url):
            # require that next_url be absolute path within our path
            allow = False
            # OR pass our cross-origin check
            if parsed.netloc:
                # if full URL, run our cross-origin check:
                origin = '%s://%s' % (parsed.scheme, parsed.netloc)
                origin = origin.lower()
                if self.allow_origin:
                    allow = self.allow_origin == origin
                elif self.allow_origin_pat:
                    allow = bool(self.allow_origin_pat.match(origin))
            if not allow:
                # not allowed, use default
                self.log.warning("Not allowing login redirect to %r" % url)
                url = default
        self.redirect(url)

    #处理/login路径的get请求
    async def get(self):
        if self.get_argument('code', False):
            print('no jump')
            access = await self.get_authenticated_user(
                redirect_uri='http://39.97.126.112:8988/lab',
                code=self.get_argument('code'))
            user = await self.oauth2_request(
                "http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/userinfo",
                access_token=access["access_token"])
            print('user   ',user)
            # Save the user and access token with
            # e.g. set_secure_cookie.
        else:
            print('jump')
            await self.authorize_redirect(
                redirect_uri='http://39.97.126.112:8988/lab',
                client_id='client2',
                client_secret='3c1219f6-89a0-4d35-989b-5fae3cd80d79',
                scope=['openid', 'email'],
                response_type='code',
                extra_params={'response_type': 'code'})
        # if self.current_user: #当前用户已登录;在这修改为判断cookie内容
        #     next_url = self.get_argument('next', default=self.base_url)
        #     self._redirect_safe(next_url)
        # print(self.cookies)
        # if self.get_cookie('KEYCLOAK_IDENTITY_LEGACY'):
        #     print('login')
        #     next_url = self.get_argument('next', default=self.base_url)
        #     self._redirect_safe(next_url)
        # else:#跳转到登录页面
        #     print('jump')
        #     self.redirect_keycloak()

    #设置登录cookie
    @classmethod
    def set_login_cookie(cls, handler, user_id=None):
        """Call this on handlers to set the login cookie for success"""
        cookie_options = handler.settings.get('cookie_options', {})
        cookie_options.setdefault('httponly', True)
        # tornado <4.2 has a bug that considers secure==True as soon as
        # 'secure' kwarg is passed to set_secure_cookie
        if handler.settings.get('secure_cookie', handler.request.protocol == 'https'):
            cookie_options.setdefault('secure', True)
        cookie_options.setdefault('path', handler.base_url)
        handler.set_secure_cookie(handler.cookie_name, user_id, **cookie_options)
        print(handler.cookie_name)
        return user_id

    auth_header_pat = re.compile('token\s+(.+)', re.IGNORECASE)

    #获取用户token作为id
    @classmethod
    def get_token(cls, handler):
        """Get the user token from a request

        Default:

        - in URL parameters: ?token=<token>
        - in header: Authorization: token <token>
        """
        #是否颙tokne，没有就去header或url里去拿‘Authorization’
        user_token = handler.get_argument('token', '')
        if not user_token:
            # get it from Authorization header
            m = cls.auth_header_pat.match(handler.request.headers.get('Authorization', ''))
            if m:
                user_token = m.group(1)
        return user_token

    @classmethod
    def should_check_origin(cls, handler):
        """Should the Handler check for CORS origin validation?

        Origin check should be skipped for token-authenticated requests.

        Returns:
        - True, if Handler must check for valid CORS origin.
        - False, if Handler should skip origin check since requests are token-authenticated.
        """
        return not cls.is_token_authenticated(handler)

    @classmethod
    def is_token_authenticated(cls, handler):
        """Returns True if handler has been token authenticated. Otherwise, False.

        Login with a token is used to signal certain things, such as:

        - permit access to REST API
        - xsrf protection
        - skip origin-checks for scripts
        """
        if getattr(handler, '_user_id', None) is None:
            # ensure get_user has been called, so we know if we're token-authenticated
            handler.get_current_user()
        return getattr(handler, '_token_authenticated', False)

    #获取用户id，
    @classmethod
    def get_user(cls, handler):
        """Called by handlers.get_current_user for identifying the current user.

        See tornado.web.RequestHandler.get_current_user for details.
        """
        # Can't call this get_current_user because it will collide when
        # called on LoginHandler itself.

        #判断handler是否有_user_id字段，有的话设置cookie并标记已经验证，没有则获取user_token作为id

        if getattr(handler, '_user_id', None):
            return handler._user_id
        user_id = handler.get_cookie('_user_id')
        if user_id is None:
            get_secure_cookie_kwargs  = handler.settings.get('get_secure_cookie_kwargs', {})
            user_id = handler.get_secure_cookie(handler.cookie_name, **get_secure_cookie_kwargs )
        else:
            cls.set_login_cookie(handler, user_id)
            # Record that the current request has been authenticated with a token.
            # Used in is_token_authenticated above.
            handler._token_authenticated = True
        if user_id is None:
            # If an invalid cookie was sent, clear it to prevent unnecessary
            # extra warnings. But don't do this on a request with *no* cookie,
            # because that can erroneously log you out (see gh-3365)
            if handler.get_cookie(handler.cookie_name) is not None:
                handler.log.warning("Clearing invalid/expired login cookie %s", handler.cookie_name)
                handler.clear_login_cookie()
            if not handler.login_available:
                # Completely insecure! No authentication at all.
                # No need to warn here, though; validate_security will have already done that.
                user_id = 'anonymous'

        # cache value for future retrievals on the same request
        handler._user_id = user_id
        return user_id

    #获取user_token 没有的或
    @classmethod
    def get_user_token(cls, handler):
        """Identify the user based on a token in the URL or Authorization header

        Returns:
        - uuid if authenticated
        - None if not
        """
        token = handler.token
        if not token:
            return
        # check login token from URL argument or Authorization header
        user_token = cls.get_token(handler)
        authenticated = False
        if user_token == token:
            # token-authenticated, set the login cookie
            handler.log.debug("Accepting token-authenticated connection from %s", handler.request.remote_ip)
            authenticated = True

        if authenticated:
            return uuid.uuid4().hex
        else:
            return None


    @classmethod
    def validate_security(cls, app, ssl_options=None):
        """Check the notebook application's security.

        Show messages, or abort if necessary, based on the security configuration.
        """
        if not app.ip:
            warning = "WARNING: The notebook server is listening on all IP addresses"
            if ssl_options is None:
                app.log.warning(warning + " and not using encryption. This "
                    "is not recommended.")
            if not app.password and not app.token:
                app.log.warning(warning + " and not using authentication. "
                    "This is highly insecure and not recommended.")
        else:
            if not app.password and not app.token:
                app.log.warning(
                    "All authentication is disabled."
                    "  Anyone who can connect to this server will be able to run code.")

    #设置密码
    @classmethod
    def password_from_settings(cls, settings):
        """Return the hashed password from the tornado settings.

        If there is no configured password, an empty string will be returned.
        """
        return settings.get('password', u'')

    #是否需要登陆
    @classmethod
    def get_login_available(cls, settings):
        """Whether this LoginHandler is needed - and therefore whether the login page should be displayed."""
        return bool(cls.password_from_settings(settings) or settings.get('token'))




class KeycloakOAuth2LoginHandler(tornado.web.RequestHandler,
                                 KeycloakOAuth2Mixin):
    async def get(self):

        if self.get_argument("code", False):
            print('getcode')
            print(self.get_argument('code'))
            access = await self.get_authenticated_user(
                redirect_uri='http://39.97.126.112:8988/login',
                code=self.get_argument('code'))
            http = httpclient.AsyncHTTPClient()
            all_args={}
            url='http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/userinfo'
            body = urllib.parse.urlencode({"access_token":access["access_token"] })
            response = await http.fetch(url,
                                        method = "POST",
                                        headers = {"Content-Type": "application/x-www-form-urlencoded"},
                                        body=body)
            user = escape.json_decode(response.body)
            # user = await self.oauth2_request(
            #     "http://39.97.126.112:8080/auth/realms/demo/protocol/openid-connect/userinfo",
            #     access_token=access["access_token"])
            print(user)
            self.set_cookie('access_token',access["access_token"])
            self.set_cookie('_user_id',user['sub'])
            self.set_cookie('username', user['preferred_username'])
            self.set_cookie('avatar', user['avatar'].replace('"','').replace("'",''))
            self.redirect('/lab')
            # print(user)
            # Save the user and access token with
            # e.g. set_secure_cookie.
        else:
            print("jump")
            self.authorize_redirect(
                redirect_uri='http://39.97.126.112:8988/login',
                client_id='client2',
                client_secret='3c1219f6-89a0-4d35-989b-5fae3cd80d79',
                scope=['openid', 'email'],
                response_type='code')

    @classmethod
    def get_user(cls, handler):
        """Called by handlers.get_current_user for identifying the current user.

        See tornado.web.RequestHandler.get_current_user for details.
        """
        # Can't call this get_current_user because it will collide when
        # called on LoginHandler itself.

        # 判断handler是否有_user_id字段，有的话设置cookie并标记已经验证，没有则获取user_token作为id
        if getattr(handler, '_user_id', None):
            return handler._user_id
        user_id = handler.get_cookie('_user_id')
        if user_id is None:
            get_secure_cookie_kwargs = handler.settings.get('get_secure_cookie_kwargs', {})
            user_id = handler.get_secure_cookie(handler.cookie_name, **get_secure_cookie_kwargs)
        else:
            #cls.set_login_cookie(handler, user_id)
            # Record that the current request has been authenticated with a token.
            # Used in is_token_authenticated above.
            handler._token_authenticated = True
        if user_id is None:
            # If an invalid cookie was sent, clear it to prevent unnecessary
            # extra warnings. But don't do this on a request with *no* cookie,
            # because that can erroneously log you out (see gh-3365)
            if handler.get_cookie(handler.cookie_name) is not None:
                handler.log.warning("Clearing invalid/expired login cookie %s", handler.cookie_name)
                handler.clear_login_cookie()
            if not handler.login_available:
                # Completely insecure! No authentication at all.
                # No need to warn here, though; validate_security will have already done that.
                user_id = 'anonymous'

        # cache value for future retrievals on the same request
        handler._user_id = user_id
        return user_id

    @classmethod
    def should_check_origin(cls, handler):
        return not cls.is_token_authenticated(handler)

    @classmethod
    def is_token_authenticated(cls, handler):
        if getattr(handler, '_user_id', None) is None:
            # ensure get_user has been called, so we know if we're token-authenticated
            handler.get_current_user()
        return getattr(handler, '_token_authenticated', False)

    @classmethod
    def get_login_available():
        """Whether this LoginHandler is needed - and therefore whether the login page should be displayed."""
        return True

    def clear_login_cookie(self):
        cookie_options = self.settings.get('cookie_options', {})
        path = cookie_options.setdefault('path', '/')
        self.clear_cookie(self.cookie_name, path=path)
        if path and path != '/':
            self.force_clear_cookie(self.cookie_name)

    def force_clear_cookie(self, name, path="/", domain=None):
        name = escape.native_str(name)
        expires = datetime.datetime.utcnow() - datetime.timedelta(days=365)

        morsel = Morsel()
        morsel.set(name, '', '""')
        morsel['expires'] = httputil.format_timestamp(expires)
        morsel['path'] = path
        if domain:
            morsel['domain'] = domain
        self.add_header("Set-Cookie", morsel.OutputString())
    # @classmethod
    # def get_user(cls,handler):
    #     """Called by handlers.get_current_user for identifying the current user.
    #
    #     See tornado.web.RequestHandler.get_current_user for details.
    #     """
    #     # Can't call this get_current_user because it will collide when
    #     # called on LoginHandler itself.
    #
    #     #判断handler是否有_user_id字段，有的话设置cookie并标记已经验证，没有则获取user_token作为id
    #
    #     if getattr(handler, '_user_id', None):
    #         return handler._user_id
    #     user_id = handler.get_cookie('_user_id')
    #     print('cookie  ',user_id)
    #     if user_id is None:
    #         get_secure_cookie_kwargs  = handler.settings.get('get_secure_cookie_kwargs', {})
    #         user_id = handler.get_secure_cookie(handler.cookie_name, **get_secure_cookie_kwargs )
    #     else:
    #         # cls.set_login_cookie(handler, user_id)
    #         # Record that the current request has been authenticated with a token.
    #         # Used in is_token_authenticated above.
    #         handler._token_authenticated = True
    #     if user_id is None:
    #         # If an invalid cookie was sent, clear it to prevent unnecessary
    #         # extra warnings. But don't do this on a request with *no* cookie,
    #         # because that can erroneously log you out (see gh-3365)
    #         if handler.get_cookie(handler.cookie_name) is not None:
    #             handler.log.warning("Clearing invalid/expired login cookie %s", handler.cookie_name)
    #             handler.clear_login_cookie()
    #         if not handler.login_available:
    #             # Completely insecure! No authentication at all.
    #             # No need to warn here, though; validate_security will have already done that.
    #             user_id = 'anonymous'
    #
    #     # cache value for future retrievals on the same request
    #     handler._user_id = user_id
    #     return user_id