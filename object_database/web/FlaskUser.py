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
from object_database.web.ActiveWebServiceSchema import request_ip_address


class FlaskUser:
    """ User class that implements to the flask-login user API.

        We make these objects from our ObjectDB User classes so that Flask can
        handle them without having to hold a view into ObjectDB
    """
    @staticmethod
    def makeFromUser(user):
        if user is None:
            return None
        else:
            return FlaskUser(user.username, user.login_expiration, user.login_ip)

    def __init__(self, username, login_expiration, login_ip):
        self.username = username
        self.login_expiration = login_expiration
        self.login_ip = login_ip

    @property
    def is_authenticated(self):
        if time.time() >= self.login_expiration:
            return False
        elif request_ip_address() != self.login_ip:
            return False
        else:
            return True

    @property
    def is_active(self):
        return True

    @property
    def is_anonymous(self):
        return True if self.username.lower() == 'anonymous' else False

    def get_id(self):
        return self.username  # must return unicode by Python 3 strings are unicode
