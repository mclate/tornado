from __future__ import absolute_import, division, print_function, with_statement
import pycares
import socket

from tornado import gen
from tornado.ioloop import IOLoop
from tornado.netutil import Resolver, is_valid_ip


class CaresResolver(Resolver):
    """Name resolver based on the c-ares library.

    This is a non-blocking and non-threaded resolver.  It may not produce
    the same results as the system resolver, but can be used for non-blocking
    resolution when threads cannot be used.

    c-ares fails to resolve some names when ``family`` is ``AF_UNSPEC``,
    so it is only recommended for use in ``AF_INET`` (i.e. IPv4).  This is
    the default for ``tornado.simple_httpclient``, but other libraries
    may default to ``AF_UNSPEC``.

    .. versionchanged:: 4.1
       The ``io_loop`` argument is deprecated.
    """
    RTYPES = {
        'A': pycares.QUERY_TYPE_A,
        'AAAA': pycares.QUERY_TYPE_AAAA,
        'CNAME': pycares.QUERY_TYPE_CNAME,
        'MX': pycares.QUERY_TYPE_MX,
        'NAPTR': pycares.QUERY_TYPE_NAPTR,
        'NS': pycares.QUERY_TYPE_NS,
        'PTR': pycares.QUERY_TYPE_PTR,
        'SOA': pycares.QUERY_TYPE_SOA,
        'SRV': pycares.QUERY_TYPE_SRV,
        'TXT': pycares.QUERY_TYPE_TXT,
    }

    def initialize(self, io_loop=None):
        self.io_loop = io_loop or IOLoop.current()
        self.channel = pycares.Channel(sock_state_cb=self._sock_state_cb)
        self.fds = {}

    def _sock_state_cb(self, fd, readable, writable):
        state = ((IOLoop.READ if readable else 0) |
                 (IOLoop.WRITE if writable else 0))
        if not state:
            self.io_loop.remove_handler(fd)
            del self.fds[fd]
        elif fd in self.fds:
            self.io_loop.update_handler(fd, state)
            self.fds[fd] = state
        else:
            self.io_loop.add_handler(fd, self._handle_events, state)
            self.fds[fd] = state

    def _handle_events(self, fd, events):
        read_fd = pycares.ARES_SOCKET_BAD
        write_fd = pycares.ARES_SOCKET_BAD
        if events & IOLoop.READ:
            read_fd = fd
        if events & IOLoop.WRITE:
            write_fd = fd
        self.channel.process_fd(read_fd, write_fd)

    @gen.coroutine
    def resolve(self, host, port, family=0):
        if is_valid_ip(host):
            addresses = [host]
        else:
            # gethostbyname doesn't take callback as a kwarg
            self.channel.gethostbyname(host, family, (yield gen.Callback(1)))
            callback_args = yield gen.Wait(1)
            assert isinstance(callback_args, gen.Arguments)
            assert not callback_args.kwargs
            result, error = callback_args.args
            if error:
                raise Exception('C-Ares returned error %s: %s while resolving %s' %
                                (error, pycares.errno.strerror(error), host))
            addresses = result.addresses
        addrinfo = []
        for address in addresses:
            if '.' in address:
                address_family = socket.AF_INET
            elif ':' in address:
                address_family = socket.AF_INET6
            else:
                address_family = socket.AF_UNSPEC
            if family != socket.AF_UNSPEC and family != address_family:
                raise Exception('Requested socket family %d but got %d' %
                                (family, address_family))
            addrinfo.append((address_family, (address, port)))
        raise gen.Return(addrinfo)

    @gen.coroutine
    def query(self, hostname, record_type):
        """Query DNS server and return list of results (based on record type).

        Accept ``hostname`` to resolve and ``record_type``.
        Supported ``record_type`` values are (case-insensitive):

        * A
        * AAAA
        * CNAME
        * MX
        * NAPTR
        * NS
        * PTR
        * SOA
        * SRV
        * TXT

        """
        assert record_type.upper() in self.RTYPES, 'Incorrect record type'
        query_type = self.RTYPES[record_type.upper()]

        self.channel.query(hostname, query_type, (yield gen.Callback(1)))
        callback_args = yield gen.Wait(1)
        assert isinstance(callback_args, gen.Arguments)
        assert not callback_args.kwargs
        result, error = callback_args.args
        if error:
            raise Exception('C-Ares returned error %s: %s while resolving %s' %
                            (error, pycares.errno.strerror(error), hostname))
        raise gen.Return(result)
