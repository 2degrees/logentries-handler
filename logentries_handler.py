##############################################################################
#
# Copyright (c) 2015, 2degrees Limited.
# All Rights Reserved.
#
# This file is part of logentries-handler
# <https://github.com/2degrees/logentries-handler/>, which is subject to the
# provisions of the BSD at
# <http://dev.2degreesnetwork.com/p/2degrees-license.html>. A copy of the
# license should accompany this distribution. THIS SOFTWARE IS PROVIDED "AS IS"
# AND ANY AND ALL EXPRESS OR IMPLIED WARRANTIES ARE DISCLAIMED, INCLUDING, BUT
# NOT LIMITED TO, THE IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST
# INFRINGEMENT, AND FITNESS FOR A PARTICULAR PURPOSE.
#
##############################################################################

from contextlib import contextmanager
from logging import Handler
from socket import SHUT_RDWR
from socket import socket as make_socket
from ssl import CERT_REQUIRED
from ssl import wrap_socket as ssl_wrap_socket
from threading import Thread

from certifi import where as get_ca_certificates_file_path

from django.conf import settings


# Use TLS 1.2 if available (requires Python 2.7.9+)
try:
    from ssl import PROTOCOL_TLSv1_2 as CHANNEL_ENCRYPTION_PROTOCOL
except ImportError:
    from ssl import PROTOCOL_TLSv1 as CHANNEL_ENCRYPTION_PROTOCOL


_API_URL = 'data.logentries.com'

_API_TLS_PORT = 443

_UNICODE_LINE_SEPARATOR = u'\u2028'

_CA_CERTIFICATES_FILE_PATH = get_ca_certificates_file_path()


class LogentriesHandler(Handler):

    def __init__(self, token):
        super(LogentriesHandler, self).__init__()

        self.token = token

    def emit(self, record):
        message = self.format(record)
        message = \
            u'%s [%s] %s' % (self.token, settings.VIRTUALENV_NAME, message)
        Thread(target=_send_message, args=(message,)).start()

    def format(self, record):
        message = super(LogentriesHandler, self).format(record)
        message = message.rstrip('\n')

        if not isinstance(message, unicode):
            message = unicode(message, 'utf-8')

        # Logentries would split logs on the ASCII line separator character
        multiline = message.replace('\n', _UNICODE_LINE_SEPARATOR)

        return multiline


def _send_message(message):
    # The message must end with an ASCII new line, or else the log may get lost
    message = message.encode('utf-8') + '\n'
    with _make_ssl_socket() as socket:
        socket.send(message)


@contextmanager
def _make_ssl_socket():
    socket = ssl_wrap_socket(
        make_socket(),
        cert_reqs=CERT_REQUIRED,
        ssl_version=CHANNEL_ENCRYPTION_PROTOCOL,
        ca_certs=_CA_CERTIFICATES_FILE_PATH,
        )
    socket.connect((_API_URL, _API_TLS_PORT))

    yield socket

    socket.shutdown(SHUT_RDWR)
    socket.close()
