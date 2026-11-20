# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

import socket


class SSHException(Exception):
    """
    Exception raised by failures in SSH2 protocol negotiation or logic errors.
    """

    pass


class AuthenticationException(SSHException):
    """
    Exception raised when authentication failed for some reason.  It may be
    possible to retry with different credentials.  (Other classes specify more
    specific reasons.)

    .. versionadded:: 1.6
    """

    pass


class PasswordRequiredException(AuthenticationException):
    """
    Exception raised when a password is needed to unlock a private key file.
    """

    pass


class BadAuthenticationType(AuthenticationException):
    """
    Exception raised when an authentication type (like password) is used, but
    the server isn't allowing that type.  (It may only allow public-key, for
    example.)

    .. versionadded:: 1.1
    """

    allowed_types = []

    # TODO (backwards incompat): remove explanation kwarg
    def __init__(self, explanation, types):
        # TODO (backwards incompat): remove this supercall unless it's actually
        # required for pickling (after fixing pickling)
        AuthenticationException.__init__(self, explanation, types)
        self.explanation = explanation
        self.allowed_types = types

    def __str__(self):
        return "{}; allowed types: {!r}".format(
            self.explanation, self.allowed_types
        )


class PartialAuthentication(AuthenticationException):
    """
    An internal exception thrown in the case of partial authentication.
    """

    allowed_types = []

    def __init__(self, types):
        AuthenticationException.__init__(self, types)
        self.allowed_types = types

    def __str__(self):
        return "Partial authentication; allowed types: {!r}".format(
            self.allowed_types
        )


# TODO (backwards incompat): stop inheriting from SSHException, move to auth.py
class UnableToAuthenticate(AuthenticationException):
    pass


class ChannelException(SSHException):
    """
    Exception raised when an attempt to open a new `.Channel` fails.

    :param int code: the error code returned by the server

    .. versionadded:: 1.6
    """

    def __init__(self, code, text):
        SSHException.__init__(self, code, text)
        self.code = code
        self.text = text

    def __str__(self):
        return "ChannelException({!r}, {!r})".format(self.code, self.text)


class BadHostKeyException(SSHException):
    """
    The host key given by the SSH server did not match what we were expecting.

    :param str hostname: the hostname of the SSH server
    :param PKey got_key: the host key presented by the server
    :param PKey expected_key: the host key expected

    .. versionadded:: 1.6
    """

    def __init__(self, hostname, got_key, expected_key):
        SSHException.__init__(self, hostname, got_key, expected_key)
        self.hostname = hostname
        self.key = got_key
        self.expected_key = expected_key

    def __str__(self):
        msg = (
            "Host key for server '{}' does not match: got '{}', expected '{}'"
        )
        return msg.format(
            self.hostname,
            self.key.get_base64(),
            self.expected_key.get_base64(),
        )


class IncompatiblePeer(SSHException):
    """
    A disagreement arose regarding an algorithm required for key exchange.

    .. versionadded:: 2.9

    .. versionchanged:: 5.2
        Failures raised by the KEXINIT cross-check now carry structured
        diagnostics describing *which* negotiation stage failed and *what*
        each end offered for it, so diagnosis no longer requires a packet
        capture:

        - ``stage``: one of ``"kex"``, ``"keys"``, ``"ciphers"``, ``"macs"``
          or ``"compression"`` (matching the keys accepted by
          ``Transport(disabled_algorithms=...)``); ``None`` when the
          exception was raised outside the KEXINIT cross-check.
        - ``local_algorithms``: tuple of the algorithm names *this*
          transport offered for the stage, in its own preference order.
        - ``remote_algorithms``: tuple of the algorithm names the *peer*
          offered for the stage, in the order the peer advertised them. For
          the directional stages (ciphers, macs, compression) both
          attributes mirror the first direction whose offers do not
          intersect; see ``directions`` for the complete picture.
        - ``directions``: ``None`` for the single-list stages (kex, keys),
          otherwise an ordered tuple of ``(direction, local, remote)``
          triples, where ``direction`` is ``"client->server"`` or
          ``"server->client"``. Direction names are role independent, so
          they mean the same thing on both ends of the connection.
        - ``summary``: the legacy one-line reason, preserved verbatim at the
          front of the rendered message.

        Handshake-internal markers that merely look like algorithms, i.e.
        names prefixed with ``ext-info-`` or ``kex-strict-``, are never
        included in the tuples above nor in the rendered message.

        The rendered message appends the structured detail to the legacy
        one-liner, using one identical shape for every stage, e.g.
        ``Incompatible ssh peer (no acceptable kex algorithm): stage=kex
        local=[...] remote=[...]``. For directional stages each failing
        direction is reported as ``<direction> local=[...] remote=[...]``.
    """

    def __init__(
        self,
        message=None,
        *,
        stage=None,
        local_algorithms=(),
        remote_algorithms=(),
        directions=None,
    ):
        self.stage = stage
        self.local_algorithms = tuple(local_algorithms)
        self.remote_algorithms = tuple(remote_algorithms)
        # (direction, local, remote) triples; None for single-list stages.
        self.directions = (
            None
            if directions is None
            else tuple(
                (name, tuple(local), tuple(remote))
                for (name, local, remote) in directions
            )
        )
        self.summary = message
        detail = self._format_detail()
        if detail:
            if message is None:
                message = detail
            else:
                message = "{}: {}".format(message, detail)
        SSHException.__init__(self, message)

    @staticmethod
    def _format_list(algorithms):
        if not algorithms:
            return "[]"
        return "[{}]".format(", ".join(algorithms))

    def _format_detail(self):
        # Single, shared shape for all stages so log scraping / test
        # assertions don't need per-stage special cases.
        if self.stage is None:
            return ""
        parts = []
        for name, local, remote in self.directions or ():
            if set(local) & set(remote):
                # This direction actually had a usable overlap; only the
                # direction(s) which failed are interesting.
                continue
            parts.append(
                "{} local={} remote={}".format(
                    name,
                    self._format_list(local),
                    self._format_list(remote),
                )
            )
        if not parts:
            parts.append(
                "local={} remote={}".format(
                    self._format_list(self.local_algorithms),
                    self._format_list(self.remote_algorithms),
                )
            )
        return "stage={} {}".format(self.stage, "; ".join(parts))


class ProxyCommandFailure(SSHException):
    """
    The "ProxyCommand" found in the .ssh/config file returned an error.

    :param str command: The command line that is generating this exception.
    :param str error: The error captured from the proxy command output.
    """

    def __init__(self, command, error):
        SSHException.__init__(self, command, error)
        self.command = command
        self.error = error

    def __str__(self):
        return 'ProxyCommand("{}") returned nonzero exit status: {}'.format(
            self.command, self.error
        )


class NoValidConnectionsError(socket.error):
    """
    Multiple connection attempts were made and no families succeeded.

    This exception class wraps multiple "real" underlying connection errors,
    all of which represent failed connection attempts. Because these errors are
    not guaranteed to all be of the same error type (i.e. different errno,
    `socket.error` subclass, message, etc) we expose a single unified error
    message and a ``None`` errno so that instances of this class match most
    normal handling of `socket.error` objects.

    To see the wrapped exception objects, access the ``errors`` attribute.
    ``errors`` is a dict whose keys are address tuples (e.g. ``('127.0.0.1',
    22)``) and whose values are the exception encountered trying to connect to
    that address.

    It is implied/assumed that all the errors given to a single instance of
    this class are from connecting to the same hostname + port (and thus that
    the differences are in the resolution of the hostname - e.g. IPv4 vs v6).

    .. versionadded:: 1.16
    """

    def __init__(self, errors):
        """
        :param dict errors:
            The errors dict to store, as described by class docstring.
        """
        addrs = sorted(errors.keys())
        body = ", ".join([x[0] for x in addrs[:-1]])
        tail = addrs[-1][0]
        if body:
            msg = "Unable to connect to port {0} on {1} or {2}"
        else:
            msg = "Unable to connect to port {0} on {2}"
        super().__init__(
            None,
            msg.format(addrs[0][1], body, tail),  # stand-in for errno
        )
        self.errors = errors

    def __reduce__(self):
        return (self.__class__, (self.errors,))


class CouldNotCanonicalize(SSHException):
    """
    Raised when hostname canonicalization fails & fallback is disabled.

    .. versionadded:: 2.7
    """

    pass


class ConfigParseError(SSHException):
    """
    A fatal error was encountered trying to parse SSH config data.

    Typically this means a config file violated the ``ssh_config``
    specification in a manner that requires exiting immediately, such as not
    matching ``key = value`` syntax or misusing certain ``Match`` keywords.

    .. versionadded:: 2.7
    """

    pass


class MessageOrderError(SSHException):
    """
    Out-of-order protocol messages were received, violating "strict kex" mode.

    .. versionadded:: 3.4
    """

    pass
