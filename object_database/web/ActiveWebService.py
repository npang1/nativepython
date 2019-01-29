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
#   limitations under the License.

import threading
import logging
import time
import base64
import json
import sys
import time
import argparse
import traceback
import os
import json
import gevent.socket

from object_database.util import genToken, checkLogLevelValidity
from object_database import ServiceBase, service_schema, Schema, Indexed, Index, DatabaseObject
from object_database.web.AuthPlugin import AuthPluginBase
from object_database.web.AuthContextPlugin import AuthContextPluginInterface
from object_database.web.ActiveWebServiceSchema import active_webservice_schema, request_ip_address
from object_database.web.cells import *
from typed_python import OneOf, TupleOf
from typed_python.Codebase import Codebase as TypedPythonCodebase

from gevent import pywsgi, sleep
from gevent.greenlet import Greenlet
from geventwebsocket.handler import WebSocketHandler

from flask import Flask, send_from_directory, redirect, url_for, request, render_template, flash
from flask_wtf import FlaskForm
from flask_sockets import Sockets
from flask_cors import CORS
from flask_login import LoginManager, current_user, login_user, logout_user, login_required

from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired


@active_webservice_schema.define
class AuthPlugin:
    name = Indexed(str)
    # auth plugin
    auth_context_factory = object  # a factory for AuthContextPluginInterface objects
    auth_plugins = TupleOf(OneOf(None, AuthPluginBase))
    codebase = OneOf(None, service_schema.Codebase)


@active_webservice_schema.define
class Configuration:
    service = Indexed(service_schema.Service)

    port = int
    hostname = str

    log_level = int

    auth_plugin = OneOf(None, AuthPlugin)

    # HTML template rendering args
    company_name = str


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')


class ActiveWebService(ServiceBase):
    def __init__(self, db, serviceObject, serviceRuntimeConfig):
        ServiceBase.__init__(self, db, serviceObject, serviceRuntimeConfig)
        self._logger = logging.getLogger(__name__)

    @staticmethod
    def setAuthPlugin(db, serviceObject, authPluginContextFactory, authPlugins, codebase=None):
        """Subclasses should take the remaining args from the commandline and configure using them"""
        db.subscribeToType(Configuration)
        db.subscribeToType(AuthPlugin)

        with db.transaction():
            c = Configuration.lookupAny(service=serviceObject)
            if not c:
                c = Configuration(service=serviceObject)
            auth_plugin = AuthPlugin(
                name="an auth plugin",
                auth_context_factory=authPluginContextFactory,
                auth_plugins=TupleOf(OneOf(None, AuthPluginBase))(authPlugins),
                codebase=codebase
            )
            c.auth_plugin = auth_plugin

    @staticmethod
    def configureFromCommandline(db, serviceObject, args):
        """Subclasses should take the remaining args from the commandline and configure using them"""
        db.subscribeToType(Configuration)

        with db.transaction():
            c = Configuration.lookupAny(service=serviceObject)
            if not c:
                c = Configuration(service=serviceObject)

            parser = argparse.ArgumentParser("Configure a webservice")
            parser.add_argument("--hostname", type=str)
            parser.add_argument("--port", type=int)
            # optional arguments
            parser.add_argument("--log-level", type=str, required=False, default="INFO")
            parser.add_argument("--company-name", type=str, required=False, default="")

            parsedArgs = parser.parse_args(args)

            level_name = parsedArgs.log_level.upper()
            checkLogLevelValidity(level_name)

            c.port = parsedArgs.port
            c.hostname = parsedArgs.hostname

            c.log_level = logging.getLevelName(level_name)
            c.company_name = parsedArgs.company_name

    def initialize(self):
        self.db.subscribeToType(Configuration)
        self.db.subscribeToType(AuthPlugin)
        self.db.subscribeToSchema(service_schema)

        with self.db.transaction():
            self.app = Flask(__name__)
            CORS(self.app)
            self.sockets = Sockets(self.app)
            self.configureApp()
        self.login_manager = LoginManager(self.app)
        self.login_manager.login_view = 'login'

    def doWork(self, shouldStop):
        self._logger.info("Configuring ActiveWebService")
        with self.db.view() as view:
            config = Configuration.lookupAny(service=self.serviceObject)
            assert config, "No configuration available."
            self._logger.setLevel(config.log_level)
            host, port = config.hostname, config.port

            auth_plugin = config.auth_plugin

            codebase = auth_plugin.codebase
            if codebase is None:
                ser_ctx = TypedPythonCodebase.coreSerializationContext()
            else:
                ser_ctx = codebase.instantiate().serializationContext
            view.setSerializationContext(ser_ctx)

            self.auth_plugin = auth_plugin.auth_context_factory(self.db, auth_plugin.auth_plugins)

            # register `load_user` method with login_manager
            self.auth_plugin.load_user = self.login_manager.user_loader(self.auth_plugin.load_user)

            authorized_groups = self.auth_plugin.authorized_groups

            self.authorized_groups_text = "All"
            if authorized_groups:
                self.authorized_groups_text = ", ".join(authorized_groups)

            self.company_name = config.company_name

        self._logger.info("ActiveWebService listening on %s:%s", host, port)

        server = pywsgi.WSGIServer((host, port), self.app, handler_class=WebSocketHandler)

        server.serve_forever()

    def configureApp(self):
        instanceName = self.serviceObject.name
        self.app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or genToken()

        self.app.add_url_rule('/', endpoint=None, view_func=lambda: redirect("/services"))
        self.app.add_url_rule('/content/<path:path>', endpoint=None, view_func=self.sendContent)
        self.app.add_url_rule('/services', endpoint=None, view_func=self.sendPage)
        self.app.add_url_rule('/services/<path:path>', endpoint=None, view_func=self.sendPage)
        self.app.add_url_rule('/login', endpoint=None, view_func=self.login, methods=['GET', 'POST'])
        self.app.add_url_rule('/logout', endpoint=None, view_func=self.logout)
        self.sockets.add_url_rule('/socket/<path:path>', None, self.mainSocket)

    def authenticate(self, username, password) -> str:
        """ Attempts to authenticate with given username and password.

            Returns:
            --------
            str
                "" if no error occurred and an error message otherwise
        """
        error = self.auth_plugin.authenticate(username, password, login_ip=request_ip_address())
        if error:
            return error

        user = self.auth_plugin.load_user(username)
        login_user(user)
        return error

    def login(self):
        if current_user.is_authenticated:
            return redirect('/')

        if self.auth_plugin.bypassAuth:
            error = self.authenticate('anonymous', 'fake-pass')
            assert not error, error
            return redirect('/')
        form = LoginForm()

        if form.validate_on_submit():
            username = form.username.data
            password = form.password.data

            error = self.authenticate(username, password)
            if error:
                flash(error, 'danger')
                return render_template(
                    'login.html',
                    form=form,
                    title=self.company_name,
                    authorized_groups_text=self.authorized_groups_text
                )

            return redirect('/')

        if form.errors:
            flash(form.errors, 'danger')

        return render_template(
            'login.html',
            form=form,
            title=self.company_name,
            authorized_groups_text=self.authorized_groups_text
        )

    def logout(self):
        # FIXME: also call logout of auth_plugin
        logout_user()
        return redirect('/')

    @login_required
    def sendPage(self, path=None):
        return self.sendContent("page.html")

    def mainDisplay(self):
        def serviceCountSetter(service, ct):
            def f():
                service.target_count = ct
            return f

        serviceCounts = list(range(5)) + list(range(10,100,10)) + list(range(100,400,25)) + list(range(400,1001,100))

        buttons = Sequence([
            Padding(),
            Button(
                Sequence([Octicon('shield').color('green'), Span('Lock ALL')]),
                lambda: [s.lock() for s in service_schema.Service.lookupAll()]),
            Button(
                Sequence([Octicon('shield').color('orange'), Span('Prepare ALL')]),
                lambda: [s.prepare() for s in service_schema.Service.lookupAll()]),
            Button(
                Sequence([Octicon('stop').color('red'), Span('Unlock ALL')]),
                lambda: [s.unlock() for s in service_schema.Service.lookupAll()]),
        ])
        tabs = Tabs(
            Services=Table(
                colFun=lambda: [
                    'Service', 'Codebase Status', 'Codebase', 'Module', 'Class',
                    'Placement', 'Active', 'TargetCount', 'Cores', 'RAM', 'Boot Status'],
                rowFun=lambda:
                    sorted(service_schema.Service.lookupAll(), key=lambda s:s.name),
                headerFun=lambda x: x,
                rendererFun=lambda s, field: Subscribed(lambda:
                    Clickable(s.name, "/services/" + s.name) if field == 'Service' else
                    (   Clickable(Sequence([Octicon('stop').color('red'), Span('Unlocked')]),
                                  lambda: s.lock()) if s.isUnlocked else
                        Clickable(Sequence([Octicon('shield').color('green'), Span('Locked')]),
                                  lambda: s.prepare()) if s.isLocked else
                        Clickable(Sequence([Octicon('shield').color('orange'), Span('Prepared')]),
                                  lambda: s.unlock())) if field == 'Codebase Status' else
                    (str(s.codebase) if s.codebase else "") if field == 'Codebase' else
                    s.service_module_name if field == 'Module' else
                    s.service_class_name if field == 'Class' else
                    s.placement if field == 'Placement' else
                    Subscribed(lambda: len(service_schema.ServiceInstance.lookupAll(service=s))) if field == 'Active' else
                    Dropdown(s.target_count, [(str(ct), serviceCountSetter(s, ct)) for ct in serviceCounts])
                            if field == 'TargetCount' else
                    str(s.coresUsed) if field == 'Cores' else
                    str(s.gbRamUsed) if field == 'RAM' else
                    (Popover(Octicon("alert"), "Failed", Traceback(s.lastFailureReason or "<Unknown>")) if s.isThrottled() else "") if field == 'Boot Status' else
                    ""
                    ),
                maxRowsPerPage=50
                ),
            Hosts=Table(
                colFun=lambda: ['Connection', 'IsMaster', 'Hostname', 'RAM ALLOCATION', 'CORE ALLOCATION', 'SERVICE COUNT', 'CPU USE', 'RAM USE'],
                rowFun=lambda: sorted(service_schema.ServiceHost.lookupAll(), key=lambda s:s.hostname),
                headerFun=lambda x: x,
                rendererFun=lambda s,field: Subscribed(lambda:
                    s.connection._identity if field == "Connection" else
                    str(s.isMaster) if field == "IsMaster" else
                    s.hostname if field == "Hostname" else
                    "%.1f / %.1f" % (s.gbRamUsed, s.maxGbRam) if field == "RAM ALLOCATION" else
                    "%s / %s" % (s.coresUsed, s.maxCores) if field == "CORE ALLOCATION" else
                    str(len(service_schema.ServiceInstance.lookupAll(host=s))) if field == "SERVICE COUNT" else
                    "%2.1f" % (s.cpuUse * 100) + "%" if field == "CPU USE" else
                    ("%2.1f" % s.actualMemoryUseGB) + " GB" if field == "RAM USE" else
                    ""
                    ),
                maxRowsPerPage=50
                )
            )
        return Sequence([buttons, tabs])

    def pathToDisplay(self, path, queryArgs):
        if len(path) and path[0] == 'services':
            if len(path) == 1:
                return self.mainDisplay()

            serviceObj = service_schema.Service.lookupAny(name=path[1])

            if serviceObj is None:
                return Traceback("Unknown service %s" % path[1])

            serviceType = serviceObj.instantiateServiceType()

            if len(path) == 2:
                return (
                    Subscribed(lambda: serviceType.serviceDisplay(serviceObj, queryArgs=queryArgs))
                        .withSerializationContext(serviceObj.getSerializationContext())
                    )

            typename = path[2]

            schemas = serviceObj.findModuleSchemas()
            typeObj = None
            for s in schemas:
                typeObj = s.lookupFullyQualifiedTypeByName(typename)
                if typeObj:
                    break

            if typeObj is None:
                return Traceback("Can't find fully-qualified type %s" % typename)

            if len(path) == 3:
                return (
                    serviceType.serviceDisplay(serviceObj, objType=typename, queryArgs=queryArgs)
                        .withSerializationContext(serviceObj.getSerializationContext())
                    )

            instance = typeObj.fromIdentity(path[3])

            return (
                serviceType.serviceDisplay(serviceObj, instance=instance, queryArgs=queryArgs)
                    .withSerializationContext(serviceObj.getSerializationContext())
                )

        return Traceback("Invalid url path: %s" % path)


    def addMainBar(self, display):
        current_username = current_user.username

        return (
            HeaderBar(
                [Subscribed(lambda:
                    Dropdown(
                        "Service",
                            [("All", "/services")] +
                            [(s.name, "/services/" + s.name) for
                                s in sorted(service_schema.Service.lookupAll(), key=lambda s:s.name)]
                        ),
                    ),
                Dropdown(
                    Octicon("three-bars"),
                    [
                        (Sequence([Octicon('person'),
                                   Span('Logged in as: {}'.format(current_username))]),
                         lambda: None),
                        (Sequence([Octicon('organization'),
                                   Span('Authorized Groups: {}'.format(self.authorized_groups_text))]),
                         lambda: None),
                        (Sequence([Octicon('sign-out'),
                                   Span('Logout')]),
                         '/logout')
                    ])
                ]) +
            Main(display)
            )

    @login_required
    def mainSocket(self, ws, path):
        path = str(path).split("/")
        queryArgs = dict(request.args)
        self._logger.info("path = %s", path)
        reader = None

        try:
            self._logger.info("Starting main websocket handler with %s", ws)

            cells = Cells(self.db)
            cells.root.setRootSerializationContext(self.db.serializationContext)
            cells.root.setChild(self.addMainBar(Subscribed(lambda: self.pathToDisplay(path, queryArgs))))

            timestamps = []

            lastDumpTimestamp = time.time()
            lastDumpMessages = 0
            lastDumpFrames = 0
            lastDumpTimeSpentCalculating = 0.0

            def readThread():
                while not ws.closed:
                    msg = ws.receive()
                    if msg is None:
                        return
                    else:
                        try:
                            jsonMsg = json.loads(msg)

                            cell_id = jsonMsg.get('target_cell')
                            cell = cells[cell_id]
                            if cell is not None:
                                cell.onMessageWithTransaction(jsonMsg)
                        except Exception:
                            self._logger.error("Exception in inbound message: %s", traceback.format_exc())
                        cells.triggerIfHasDirty()

            reader = Greenlet.spawn(readThread)

            while not ws.closed:
                t0 = time.time()
                messages = cells.renderMessages()

                user = self.auth_plugin.load_user(current_user.username)
                if not user.is_authenticated:
                    ws.close()
                    return

                lastDumpTimeSpentCalculating += time.time() - t0

                for message in messages:
                    gevent.socket.wait_write(ws.stream.handler.socket.fileno())

                    ws.send(json.dumps(message))
                    lastDumpMessages += 1

                lastDumpFrames += 1
                if time.time() - lastDumpTimestamp > 5.0:
                    self._logger.info("In the last %.2f seconds, spent %.2f seconds calculating %s messages over %s frames",
                        time.time() - lastDumpTimestamp,
                        lastDumpTimeSpentCalculating,
                        lastDumpMessages,
                        lastDumpFrames
                        )

                    lastDumpFrames = 0
                    lastDumpMessages = 0
                    lastDumpTimeSpentCalculating = 0
                    lastDumpTimestamp = time.time()

                ws.send(json.dumps("postscripts"))

                cells.wait()

                timestamps.append(time.time())

                if len(timestamps) > MAX_FPS:
                    timestamps = timestamps[-MAX_FPS+1:]
                    if (time.time() - timestamps[0]) < 1.0:
                        sleep(1.0 / MAX_FPS + .001)

        except Exception:
            self._logger.error("Websocket handler error: %s", traceback.format_exc())
        finally:
            if reader:
                reader.join()

    @login_required
    def echoSocket(self, ws):
        while not ws.closed:
            message = ws.receive()
            if message is not None:
                ws.send(message)

    @login_required
    def sendContent(self, path):
        own_dir = os.path.dirname(__file__)
        return send_from_directory(os.path.join(own_dir, "content"), path)

    @staticmethod
    def serviceDisplay(serviceObject, instance=None, objType=None, queryArgs=None):
        c = Configuration.lookupAny(service=serviceObject)

        return Card(Text("Host: " + c.hostname) + Text("Port: " + str(c.port)))
