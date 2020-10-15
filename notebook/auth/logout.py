"""Tornado handlers for logging out of the notebook.
"""

# Copyright (c) Jupyter Development Team.
# Distributed under the terms of the Modified BSD License.
from tornado import httpclient

from ..base.handlers import IPythonHandler

#需要重写git logout函数
class LogoutHandler(IPythonHandler):

    def get(self):
        # logouturl='http://39.97.126.112:8090/auth/realms/demo/protocol/openid-connect/logout'
        # http = httpclient.AsyncHTTPClient()
        # response = await http.fetch(logouturl,method="GET")
        self.clear_all_cookies()
        if self.login_available:
            message = {'info': 'Successfully logged out.'}
        else:
            message = {'warning': 'Cannot log out.  Notebook authentication '
                       'is disabled.'}
        self.write(self.render_template('logout.html',
                    message=message))


default_handlers = [(r"/logout", LogoutHandler)]