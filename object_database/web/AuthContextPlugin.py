#   Copyright 2019 Nativepython Authors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.from collections import defaultdict

import time

from object_database.web.FlaskUser import FlaskUser
from typed_python import TupleOf, Float64
from object_database.web.ActiveWebServiceSchema import active_webservice_schema
from object_database.view import revisionConflictRetry
from object_database import Indexed

USER_LOGIN_DURATION = 24 * 60 * 60  # 24 hours


@active_webservice_schema.define
class User:
    username = Indexed(str)
    login_expiration = Float64()
    login_ip = str

    def login(self, login_ip):
        self.login_expiration = time.time() + USER_LOGIN_DURATION
        self.login_ip = login_ip

    def logout(self):
        self.login_expiration = 0.0
        self.login_ip = ""


class AuthContextPluginInterface:
    def __init__(self, db, auth_plugins, codebase=None):
        raise NotImplementedError("derived class must implement this method")

    def load_user(self, username) -> FlaskUser:
        raise NotImplementedError("derived class must implement this method")

    def authenticate(self, username, password, login_ip) -> str:
        """ Tries to authenticate with given username, password, and login_ip.

            Returns:
            --------
            str
                "" if no error occurred, and an error message otherwise
        """
        raise NotImplementedError("derived class must implement this method")

    @property
    def bypassAuth(self) -> bool:
        raise NotImplementedError("derived class must implement this method")

    @property
    def authorized_groups(self):
        raise NotImplementedError("derived class must implement this method")

    def logout_user(self, username):
        raise NotImplementedError("derived class must implement this method")


class AuthContextPlugin(AuthContextPluginInterface):
    def __init__(self, db, auth_plugins, codebase=None):
        self._db = db
        self._db.subscribeToType(User)
        assert len(auth_plugins) == 1
        self._auth_plugin = auth_plugins[0]
        self._codebase = codebase

    def load_user(self, username):
        with self._db.view():
            return FlaskUser.makeFromUser(User.lookupAny(username=username))

    def authenticate(self, username, password, login_ip) -> str:
        if not self.bypassAuth:
            error = self._auth_plugin.authenticate(username, password)
            if error:
                return error

        self._login_user(username, login_ip)
        return ''

    @property
    def bypassAuth(self):
        return self._auth_plugin is None

    @property
    def authorized_groups(self):
        return self._auth_plugin.authorized_groups if self._auth_plugin is not None else None

    @revisionConflictRetry
    def _login_user(self, username, login_ip):
        with self._db.transaction():
            users = User.lookupAll(username=username)

            if len(users) == 0:
                user = User(username=username)
            elif len(users) == 1:
                user = users[0]
            elif len(users) > 1:
                raise Exception("multiple users found with username={}".format(username))
            else:
                raise Exception("This should never happen: len(users)={}".format(len(users)))

            user.login(login_ip)

    @revisionConflictRetry
    def logout_user(self, username):
        with self._db.transaction():
            user = User.lookupAny(username=username)

            if user is not None:
                user.logout()
