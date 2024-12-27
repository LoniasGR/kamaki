# Copyright 2014-2015 GRNET S.A. All rights reserved.
#
# Redistribution and use in source and binary forms, with or
# without modification, are permitted provided that the following
# conditions are met:
#
#   1. Redistributions of source code must retain the above
#      copyright notice, this list of conditions and the following
#      disclaimer.
#
#   2. Redistributions in binary form must reproduce the above
#      copyright notice, this list of conditions and the following
#      disclaimer in the documentation and/or other materials
#      provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY GRNET S.A. ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL GRNET S.A OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# The views and conclusions contained in the software and
# documentation are those of the authors and should not be
# interpreted as representing official policies, either expressed
# or implied, of GRNET S.A.

import logging
import http.client
import socket
import ssl
import os.path
import http
import objpool.http as httpPool

log = logging.getLogger(__name__)


class SSLUnicodeError(ssl.SSLError):
    """SSL module cannot handle unicode file names"""


class SSLCredentialsMissing(ssl.SSLError):
    """Missing credentials for SSL authentication"""


class HTTPSClientAuthConnection(http.client.HTTPSConnection):
    """HTTPS connection, with full client-based SSL Authentication support"""

    cafile, ignore_ssl = None, False

    def __init__(self, *args, **kwargs):
        """Extent HTTPSConnection to support SSL authentication
        :param cafile: path to CA certificates bundle (default: None)
        :param ignore_ssl: flag (default: False)
        """
        self.cafile = str(kwargs.pop("cafile", self.cafile) or "") or None

        self.ignore_ssl = kwargs.pop("ignore_ssl", self.ignore_ssl)

        http.client.HTTPSConnection.__init__(self, *args, **kwargs)

    def connect(self):
        """Connect to a host on a given (SSL) port.
        Use cafile to check Server Certificate.

        Redefined/copied and extended from httplib.py:1105 (Python 2.6.x).
        This is needed to pass cert_reqs=ssl.CERT_REQUIRED as parameter to
        ssl.wrap_socket(), which forces SSL to check server certificate against
        our client certificate.
        """
        source_address = getattr(self, "source_address", None)
        socket_args = [(self.host, self.port)]
        if self.timeout is float:
            socket_args.append(self.timeout)
        if source_address:
            socket_args.append(source_address)

        sock = socket.create_connection(*socket_args)
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()

        try:
            context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            if self.ignore_ssl:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            else:
                context.load_verify_locations(cafile=self.cafile)
                context.verify_mode = ssl.CERT_REQUIRED

            self.sock = context.wrap_socket(sock, server_hostname=self.host)
        except IOError as ioe:
            # In OSX, a wrong SSL credential file may raise an IOError with
            # errno of 2, instead of an SSL error
            # Wrap it in SSL and raise it
            if getattr(ioe, "errno", None) == 2:
                files = self.keyfile, self.certfile, self.cafile
                if not any(files):
                    raise SSLCredentialsMissing(
                        "No SSL cred. files provided (IOError:%s)" % ioe
                    )
                for f in files:
                    if f and not os.path.exists(f):
                        raise SSLCredentialsMissing(
                            "SSL cred. file %s does not exist (IOError:%s)" % (f, ioe)
                        )
            raise


httpPool.HTTPConnectionPool._scheme_to_class["https"] = HTTPSClientAuthConnection
PooledHTTPConnection = httpPool.PooledHTTPConnection


def patch_with_certs(cafile):
    try:
        HTTPSClientAuthConnection.cafile = str(cafile)
    except UnicodeError as ue:
        raise SSLUnicodeError(0, SSLUnicodeError.__doc__, ue)


def patch_ignore_ssl(insecure_connection=True):
    HTTPSClientAuthConnection.ignore_ssl = insecure_connection
