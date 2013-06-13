# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import routes
import errno
import inspect
import os
import random
import signal
import sys
import time
import eventlet
import greenlet

from keystone import auth
from keystone import catalog
from keystone import config
from keystone.common import logging
from keystone.common import wsgi
from keystone.contrib import ec2
from keystone import identity
from keystone import policy
from keystone import routers
from keystone import token
from keystone import trust


CONF = config.CONF
LOG = logging.getLogger(__name__)

DRIVERS = dict(
    catalog_api=catalog.Manager(),
    ec2_api=ec2.Manager(),
    identity_api=identity.Manager(),
    policy_api=policy.Manager(),
    token_api=token.Manager(),
    trust_api=trust.Manager())


@logging.fail_gracefully
def public_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [identity.routers.Public(),
                                 token.routers.Router(),
                                 routers.VersionV2('public'),
                                 routers.Extension(False)])


@logging.fail_gracefully
def admin_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [identity.routers.Admin(),
                                    token.routers.Router(),
                                    routers.VersionV2('admin'),
                                    routers.Extension()])


@logging.fail_gracefully
def public_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('public')])


@logging.fail_gracefully
def admin_version_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return wsgi.ComposingRouter(routes.Mapper(),
                                [routers.Versions('admin')])


@logging.fail_gracefully
def v3_app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    mapper = routes.Mapper()
    v3routers = []
    for module in [auth, catalog, identity, policy]:
        module.routers.append_v3_routers(mapper, v3routers)

    if CONF.trust.enabled:
        trust.routers.append_v3_routers(mapper, v3routers)

    # Add in the v3 version api
    v3routers.append(routers.VersionV3('admin'))
    v3routers.append(routers.VersionV3('public'))
    # TODO(ayoung): put token routes here
    return wsgi.ComposingRouter(mapper, v3routers)

class SignalExit(SystemExit):
    def __init__(self, signo, exccode=1):
        super(SignalExit, self).__init__(exccode)
        self.signo = signo


class Launcher(object):
    """Launch one or more services and wait for them to complete."""

    def __init__(self):
        """Initialize the service launcher.

        :returns: None

        """
        self._services = []

    @staticmethod
    def run_server(server):
        """Start and wait for a server to finish.

        :param service: Server to run and wait for.
        :returns: None

        """
        server.start()
        server.wait()

    def launch_server(self, server):
        """Load and start the given server.

        :param server: The server you would like to start.
        :returns: None

        """
        gt = eventlet.spawn(self.run_server, server)
        self._services.append(gt)

    def stop(self):
        """Stop all services which are currently running.

        :returns: None

        """
        for service in self._services:
            service.kill()

    def wait(self):
        """Waits until all services have been stopped, and then returns.

        :returns: None

        """
        for service in self._services:
            try:
                service.wait()
            except greenlet.GreenletExit:
                pass


class ServerWrapper(object):
    def __init__(self, server, workers):
        self.server = server
        self.workers = workers
        self.children = set()
        self.forktimes = []


class ProcessLauncher(object):
    def __init__(self):
        self.children = {}
        self.sigcaught = None
        self.running = True
        rfd, self.writepipe = os.pipe()
        self.readpipe = eventlet.greenio.GreenPipe(rfd, 'r')

        signal.signal(signal.SIGTERM, self._handle_signal)
        signal.signal(signal.SIGINT, self._handle_signal)

    def _handle_signal(self, signo, frame):
        self.sigcaught = signo
        self.running = False

        # Allow the process to be killed again and die from natural causes
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)

    def _pipe_watcher(self):
        # This will block until the write end is closed when the parent
        # dies unexpectedly
        self.readpipe.read()

        LOG.info(_('Parent process has died unexpectedly, exiting'))

        sys.exit(1)

    def _child_process(self, server):
        # Setup child signal handlers differently
        def _sigterm(*args):
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            raise SignalExit(signal.SIGTERM)

        signal.signal(signal.SIGTERM, _sigterm)
        # Block SIGINT and let the parent send us a SIGTERM
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Reopen the eventlet hub to make sure we don't share an epoll
        # fd with parent and/or siblings, which would be bad
        eventlet.hubs.use_hub()

        # Close write to ensure only parent has it open
        os.close(self.writepipe)
        # Create greenthread to watch for parent to close pipe
        eventlet.spawn(self._pipe_watcher)

        # Reseed random number generator
        random.seed()

        launcher = Launcher()
        launcher.run_server(server)

    def _start_child(self, wrap):
        if len(wrap.forktimes) > wrap.workers:
            # Limit ourselves to one process a second (over the period of
            # number of workers * 1 second). This will allow workers to
            # start up quickly but ensure we don't fork off children that
            # die instantly too quickly.
            if time.time() - wrap.forktimes[0] < wrap.workers:
                LOG.info(_('Forking too fast, sleeping'))
                time.sleep(1)

            wrap.forktimes.pop(0)

        wrap.forktimes.append(time.time())

        pid = os.fork()
        if pid == 0:
            # NOTE(johannes): All exceptions are caught to ensure this
            # doesn't fallback into the loop spawning children. It would
            # be bad for a child to spawn more children.
            status = 0
            try:
                LOG.info(_('Running...'))
                self._child_process(wrap.server)
                LOG.info(_('Finished.'))
            except SignalExit as exc:
                signame = {signal.SIGTERM: 'SIGTERM',
                           signal.SIGINT: 'SIGINT'}[exc.signo]
                LOG.info(_('Caught %s, exiting'), signame)
                status = exc.code
            except SystemExit as exc:
                LOG.info(_('Exited with status %d.'), status)
                status = exc.code
            except BaseException:
                LOG.exception(_('Unhandled exception'))
                status = 2

            os._exit(status)

        LOG.info(_('Started child %d'), pid)

        wrap.children.add(pid)
        self.children[pid] = wrap

        return pid

    def launch_server(self, server, workers=1):
        wrap = ServerWrapper(server, workers)

        LOG.info(_('Starting %d workers'), wrap.workers)
        while self.running and len(wrap.children) < wrap.workers:
            self._start_child(wrap)

    def _wait_child(self):
        try:
            pid, status = os.wait()
        except OSError as exc:
            if exc.errno not in (errno.EINTR, errno.ECHILD):
                raise
            return None

        if os.WIFSIGNALED(status):
            sig = os.WTERMSIG(status)
            LOG.info(_('Child %(pid)d killed by signal %(sig)d'), locals())
        else:
            code = os.WEXITSTATUS(status)
            LOG.info(_('Child %(pid)d exited with status %(code)d'), locals())

        if pid not in self.children:
            LOG.warning(_('pid %d not in child list'), pid)
            return None

        wrap = self.children.pop(pid)
        wrap.children.remove(pid)
        return wrap

    def wait(self):
        """Loop waiting on children to die and respawning as necessary."""
        while self.running:
            wrap = self._wait_child()
            if not wrap:
                continue

            while self.running and len(wrap.children) < wrap.workers:
                self._start_child(wrap)

        if self.sigcaught:
            signame = {signal.SIGTERM: 'SIGTERM',
                       signal.SIGINT: 'SIGINT'}[self.sigcaught]
            LOG.info(_('Caught %s, stopping children'), signame)

        for pid in self.children:
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    raise

        # Wait for children to die
        if self.children:
            LOG.info(_('Waiting on %d children to exit'), len(self.children))
            while self.children:
                self._wait_child()
