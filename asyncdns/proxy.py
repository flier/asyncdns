#!/usr/bin/env python
from __future__ import with_statement

import sys
import logging
import socket
import errno
import struct

class SocksProtocolError(Exception):
    pass

class InvalidSocksVersion(SocksProtocolError):
    def __init__(self, version):
        SocksProtocolError.__init__(self, "Invalid socks version: %d" % version)

        self.version = version

class AuthenticationError(SocksProtocolError):
    def __init__(self, errcode):
        SocksProtocolError.__init__(self, "Invalid username or password: %d" % errcode)

class NoAcceptableAuthMethod(SocksProtocolError):
    def __init__(self):
        SocksProtocolError.__init__(self, "No acceptable authentication method")

class SocksProtocol(object):
    logger = logging.getLogger("asyncdns.socks")

    VER_SOCKS_4 = 4
    VER_SOCKS_5 = 5

    METHOD_NO_AUTH = 0
    METHOD_GSSAPI = 1
    METHOD_SIMPLE = 2
    METHOD_NO_ACCEPTABLE = 255

    AUTH_SIMPLE_VERSION = 1

    CMD_CONNECT = 1
    CMD_BIND = 2
    CMD_UDP_ASSOCIATE = 3

    ADDR_TYPE_IPV4 = 1
    ADDR_TYPE_DOMAIN = 3
    ADDR_TYPE_IPV6 = 4

    REPLY_MESSAGE = [
        'succeeded',
        'general SOCKS server failure',
        'connection not allowed by ruleset',
        'network unreachable',
        'host unreachable',
        'connection refused',
        'TTL expired',
        'command not supported',
        'address type not supported',
    ]

    def __init__(self, sock, username='', passwd='', version=VER_SOCKS_5):
        if version not in [self.VER_SOCKS_5]:
            raise InvalidSocksVersion(version)

        self.sock = sock
        self.username = username
        self.passwd = passwd
        self.version = version

    def recvall(self, bytes):
        buf = ""

        while len(buf) < bytes:
            buf += self.sock.recv(bytes-len(buf))

        return buf

    def make_connect(self, methods=[METHOD_NO_AUTH, METHOD_SIMPLE]):
        if methods in [[], None]:
            methods = [self.METHOD_NO_AUTH]

        buf = struct.pack("2B", self.version, len(methods))
        buf += ''.join([chr(method) for method in methods])

        return buf

    def parse_connect(self):
        version, method = struct.unpack("2B", self.recvall(2))

        if version != self.version:
            raise InvalidSocksVersion(version)

        if method == self.METHOD_NO_ACCEPTABLE:
            raise NoAcceptableAuthMethod()

        self.auth_method = method

        return self.auth_method

    def connect(self):
        self.logger.info("sending a connect request to proxy %s:%d", *self.sock.getpeername())

        self.sock.sendall(self.make_connect())

        method = self.parse_connect()

        self.logger.info("received the connect reply with authentication method %d", method)

        if self.METHOD_SIMPLE == method:
            self.simple_auth(self.username, self.passwd)

        return True

    def make_simple_auth(self, username, passwd):
        return chr(self.AUTH_SIMPLE_VERSION) + \
               chr(len(username)) + username + \
               chr(len(passwd)) + passwd

    def parse_simple_auth(self):
        version, reply_code = struct.unpack("2B", self.recvall(2))

        if version != self.AUTH_SIMPLE_VERSION:
            raise InvalidSocksVersion(version)

        if reply_code != 0:
            self.sock.close()
            raise AuthenticationError(reply_code)

        return True

    def simple_auth(self, username, passwd):
        self.logger.info("sending a simple authentication request to proxy")

        self.sock.sendall(self.make_simple_auth(username, passwd))

        return self.parse_simple_auth()

    def make_request(self, cmd, host='0.0.0.0', port=0):
        buf = struct.pack("3B", self.version, cmd, 0)

        try:
            buf += chr(self.ADDR_TYPE_IPV4) + socket.inet_aton(host)
        except socket.error:
            buf += chr(self.ADDR_TYPE_DOMAIN) + chr(len(host)) + host

        buf += struct.pack(">H", port)

        return buf

    def parse_request(self):
        version, reply_code, _, addr_type = struct.unpack("4B", self.recvall(4))

        if version != self.version:
            raise InvalidSocksVersion(version)

        if reply_code == 0:
            pass
        elif reply_code in range(len(self.REPLY_MESSAGE)):
            raise SocksProtocolError(self.REPLY_MESSAGE[reply_code])
        else:
            raise SocksProtocolError("unknown reply code: %d" % reply_code)

        if addr_type == self.ADDR_TYPE_IPV4:
            host = socket.inet_ntoa(self.recvall(4))
        elif addr_type == self.ADDR_TYPE_DOMAIN:
            host = self.recvall(ord(self.recvall(1)))
        else:
            raise SocksProtocolError("unsupport address type: %d" % addr_type)

        port = struct.unpack(">H", self.recvall(2))[0]

        return host, port

    def associate(self, host='0.0.0.0', port=0):
        self.logger.info("sending a UDP associate request to proxy %s:%d", *self.sock.getpeername())

        self.sock.sendall(self.make_request(self.CMD_UDP_ASSOCIATE, host, port))

        proxy_host, proxy_port = self.parse_request()

        self.logger.info("associated the UDP proxy @ %s:%d", proxy_host, proxy_port)

        return proxy_host, proxy_port

    def make_packet(self, host, port, data):
        buf = "\x00\x00\x00"

        try:
            buf += chr(self.ADDR_TYPE_IPV4) + socket.inet_aton(host)
        except socket.error:
            buf += chr(self.ADDR_TYPE_DOMAIN) + chr(len(host)) + host

        buf += struct.pack(">H", port)
        buf += data

        return buf

    def parse_packet(self, buf):
        _, fragment_num, addr_type = struct.unpack("H2B", buf[:4])

        pos = 4

        if addr_type == self.ADDR_TYPE_IPV4:
            host = socket.inet_ntoa(buf[pos:pos+4])
            pos += 4

        elif addr_type == self.ADDR_TYPE_DOMAIN:
            len = ord(buf[pos])
            pos += 1

            host = buf[pos:pos+len]
            pos += len
        else:
            raise SocksProtocolError("unsupport address type: %d" % addr_type)

        port = struct.unpack(">H", buf[pos:pos+2])[0]

        pos += 2

        return host, port, buf[pos:]

class SocksProxy(object):
    """

    SocksProxy is a socks 5 proxy client for the UDP protocol


    RFC1928 - SOCKS Protocol Version 5
        http://www.faqs.org/rfcs/rfc1928.html

    RFC1929 - Username/Password Authentication for SOCKS V5
        http://www.faqs.org/rfcs/rfc1929.html

    """
    logger = logging.getLogger("asyncdns.proxy")

    def __init__(self, host, port, username='', passwd='',
                 version=SocksProtocol.VER_SOCKS_5, timeout=5):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)

        self.proto = SocksProtocol(self.sock, username, passwd, version)
        self.host = host
        self.port = port
        self.username = username
        self.passwd = passwd

    def __enter__(self):
        if self.connect():
            self.open()

        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def connect(self):
        self.logger.debug("connecting to proxy @ %s:%d", self.host, self.port)

        errcode = self.sock.connect_ex((self.host, self.port))

        self.connected = 0 == errcode

        if not self.connected:
            self.logger.warn("fail to connect proxy @ %s:%d, %d %s",
                             self.host, self.port, errcode, errno.errorcode[errcode])
        else:
            self.logger.info("connected to proxy @ %s:%d", self.host, self.port)

        return self.connected

    def close(self):
        if self.connected:
            self.sock.close()

    def open(self):
        return self.proto.connect()

    def wrapped_sendto(self, proxy, sendto):
        def wrapped(data, flags, addr=None):
            if addr is None:
                addr = flags
                flags = 0

            host, port = addr

            packet = self.proto.make_packet(host, port, data)

            sent = sendto(packet, flags, proxy)

            return sent - (len(packet) - len(data))

        return wrapped

    def wrapped_recvfrom(self, proxy, recvfrom):
        def wrapped(bufsize, flags=0):
            data, addr = recvfrom(bufsize, flags)

            host, port, data = self.proto.parse_packet(data)

            return data, (host, port)

        return wrapped

    def wrap(self, sock):
        sock.bind(('0.0.0.0', 0))

        host, port = sock.getsockname()

        addr = self.proto.associate(host, port)

        sock.sendto = self.wrapped_sendto(addr, sock.sendto)
        sock.recvfrom = self.wrapped_recvfrom(addr, sock.recvfrom)

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    args = [arg for arg in sys.argv[1:] if arg[0] != '-']
    domain = args.pop(0)
    host = args.pop(0)
    port = int(args.pop(0))
    username = args.pop(0) if args else None
    passwd = args.pop(0) if args else None

    with SocksProxy(host, port, username, passwd) as proxy:
        import dns.name
        import dns.rdatatype
        import dns.message

        qname = dns.name.from_text(domain, None)
        request = dns.message.make_query(qname, dns.rdatatype.ANY)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        proxy.wrap(sock)

        sent = sock.sendto(request.to_wire(), ("8.8.8.8", 53))

        print "INFO: sent %d bytes through proxy" % sent

        packet, addr = sock.recvfrom(1024)

        print "INFO: received %d bytes packet from %s" % (len(packet), addr)

        response = dns.message.from_wire(packet)

        print "INFO: response=", response
