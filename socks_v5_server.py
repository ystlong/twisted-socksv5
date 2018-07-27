# -*- coding: utf-8 -*-
# @Author: ystlong
# @Date:   2018-07-22 15:44:56
# @Last Modified by:   ystlong
# @Last Modified time: 2018-07-28 01:32:00

# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

import sys
import os
boot_dir = os.path.dirname(__file__)
sys.path.append(os.path.join(boot_dir, "3rdpart/Twisted-18.7.0/src"))
sys.path.append(os.path.join(boot_dir, "3rdpart/incremental-17.5.0/src/"))
sys.path.append(os.path.join(boot_dir, "3rdpart/zope.interface-4.5.0/src/"))
sys.path.append(os.path.join(boot_dir, "3rdpart/constantly-15.1.0/"))
# sys.path.append(os.path.join(boot_dir, "3rdpart/attr-0.3.1/"))
sys.path.append(os.path.join(boot_dir, "3rdpart/attrs-18.1.0/src/"))
sys.path.append(os.path.join(boot_dir, "3rdpart/service_identity-17.0.0/src/"))



from twisted.internet import protocol, reactor, endpoints
from twisted.internet import reactor
from twisted.internet.protocol import Protocol, ClientFactory
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
import struct
from twisted.python import log
import crypt

class SocksV5(object):
    """docstring for SocksV5"""
    def __init__(self, server):
        super(SocksV5, self).__init__()
        self.isverify = False
        self.ishansol = False
        self.server = server


    def parse_data(self, data):
        res = data
        if not self.ishansol:
            res = self.stage_hand(data)
        elif not self.isverify:
            res = self.connect_client(data)
        return res

    def stage_hand(self, data):
        rep = '\x05\xFF' # socksv5 magic header
        if len(data) < 3:
            print "error reequest"
        else:
            ver = ord(data[0])
            nmethod = ord(data[1])
            suSocks5Endort_method = 0
            if ver == 5:
                for i in xrange(nmethod):
                    # print "find client suSocks5Endort method", ord(data[2+i])
                    if ord(data[2+i]) == suSocks5Endort_method:
                        # print "find suSocks5Endort socks auth method"
                        rep = '\x05\x00'
                        break
        self.ishansol = True
        return rep

    # **第二步**
    #   一旦方法选择子商议结束，客户机就发送请求细节。如果商议方法包括了完整性检查的目的或机密性封装
    #   ，则请求必然被封在方法选择的封装中。 

    #   SOCKS请求如下表所示:
    #   +----+-----+-------+------+----------+----------+ 
    #   | VER| CMD | RSV   | ATYP |  DST.ADDR|  DST.PORT|
    #   +----+-----+-------+------+----------+----------+ 
    #   | 1  | 1   | X'00' | 1    | variable |      2   |
    #   +----+-----+-------+------+----------+----------+ 

    #   各个字段含义如下:
    #   VER  版本号X'05'
    #   CMD：  
    #        1. CONNECT X'01'
    #        2. BIND    X'02'
    #        3. UDP ASSOCIATE X'03'
    #   RSV  保留字段
    #   ATYP IP类型 
    #        1.IPV4 X'01'
    #        2.DOMAINNAME X'03'
    #        3.IPV6 X'04'
    #   DST.ADDR 目标地址 
    #        1.如果是IPv4地址，这里是big-endian序的4字节数据
    #        2.如果是FQDN，比如"www.nsfocus.net"，这里将是:
    #          0F 77 77 77 2E 6E 73 66 6F 63 75 73 2E 6E 65 74
    #          注意，没有结尾的NUL字符，非ASCIZ串，第一字节是长度域
    #        3.如果是IPv6地址，这里是16字节数据。
    #   DST.PORT 目标端口（按网络次序排列） 
    # **sock5响应如下:**
    #  OCKS Server评估来自SOCKS Client的转发请求并发送响应报文:
    #  +----+-----+-------+------+----------+----------+
    #  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    #  +----+-----+-------+------+----------+----------+
    #  | 1  |  1  | X'00' |  1   | Variable |    2     |
    #  +----+-----+-------+------+----------+----------+
    #  VER  版本号X'05'
    #  REP  
    #       1. 0x00        成功
    #       2. 0x01        一般性失败
    #       3. 0x02        规则不允许转发
    #       4. 0x03        网络不可达
    #       5. 0x04        主机不可达
    #       6. 0x05        连接拒绝
    #       7. 0x06        TTL超时
    #       8. 0x07        不支持请求包中的CMD
    #       9. 0x08        不支持请求包中的ATYP
    #       10. 0x09-0xFF   unassigned
    def connect_client(self, data):
        # print "fetch cmd"
        # default faild 1
        rep = "\x05\x01\x00\x00\x00\x00\x00\x00\x00\x00"
        issuSocks5Endort = False
        if len(data) < 6:
            print "error request Socks5Front cmd"
        elif data[0] == "\x05" and data[1] == "\x01":
            # connect
            atype_ip = '\x01'
            ip = None
            if data[3] == atype_ip:
                # dest_ip = data[4:8]
                # print_byte(dest_ip)
                dest_ip = "%s.%s.%s.%s"%(ord(data[4]), ord(data[5]), ord(data[6]), ord(data[7]))
                # port = ord(data[8:10])
                dest_port = struct.unpack("!H", data[8:10])[0]
                print "request: %s:%s"%(dest_ip, dest_port)
                self.server.start_client(dest_ip, dest_port)
                rep = None
            elif data[3] == '\x03':
                # domain
                # print ord(data[4])
                # domain_len = struct.unpack("!B", data[4:5])[0]
                domain_len = ord(data[4])
                dest_domain = data[5:5+domain_len]
                dest_port = struct.unpack("!H", data[5+domain_len:7+domain_len])[0]
                self.server.start_client(dest_domain, dest_port)
                # print repr(dest_domain), dest_port
                # print "atype not support"
                rep = None
        return rep

class Proxy(protocol.Protocol):
    noisy = True
    peer = None

    def setPeer(self, peer):
        self.peer = peer

    def connectionLost(self, reason):
        if self.peer is not None:
            self.peer.transport.loseConnection()
            self.peer = None
        elif self.noisy:
            log.msg("Unable to connect to peer: %s" % (reason,))

class ProxyClient(Proxy):

    def dataReceived(self, data):
        self.peer.transport_write(data)

    def connectionMade(self):
        self.peer.setPeer(self)
        # Wire this and the peer transport together to enable
        # flow control (this stops connections from filling
        # this proxy memory when one side produces data at a
        # higher rate than the other can consume).
        self.transport.registerProducer(self.peer.transport, True)
        self.peer.transport.registerProducer(self.transport, True)

        # We're connected, everybody can read to their hearts content.
        self.peer.transport.resumeProducing()

        self.peer.client_conn_ok(self.transport.getHost())


class ProxyClientFactory(protocol.ClientFactory):

    protocol = ProxyClient
    server = None

    def setServer(self, server):
        self.server = server

    def buildProtocol(self, *args, **kw):
        prot = protocol.ClientFactory.buildProtocol(self, *args, **kw)
        prot.setPeer(self.server)
        return prot

    def clientConnectionFailed(self, connector, reason):
        self.server.transport.loseConnection()


class ProxyServer(Proxy):

    clientProtocolFactory = ProxyClientFactory
    reactor = None
    socksv5 = None

    def connectionMade(self):
        self.sockv5 = SocksV5(self)

    def transport_write(self, data):
        data = self.factory.crypto.encrypt(data)
        # print "send datalen: ", len(data)
        self.transport.write(data)

    def dataReceived(self, data):
        data = self.factory.crypto.decrypt(data)
        # print "server data dataReceived===", repr(data), "--"
        if self.sockv5.isverify:
            self.peer.transport.write(data)
        else:
            res = self.sockv5.parse_data(data)
            if res != None:
                # print "====== sockv5 parse_data: ", repr(data)
                self.transport_write(res)
                # self.transport.write(res)

    def start_client(self, host, port):
        # Don't read anything from the connecting client until we have
        # somewhere to send it to.
        self.transport.pauseProducing()

        client = ProxyClientFactory()
        client.setServer(self)

        if self.reactor is None:
            # from twisted.internet import reactor
            self.reactor = reactor
        self.reactor.connectTCP(host, port, client)

    def client_conn_ok(self, addr):
        # print "***** client_conn_ok"
        # default conn success
        # rep = "\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        ips = []
        for i in addr.host.split("."):
            ips.append(int(i))
        s = struct.pack("!BBBBH", ips[0], ips[1], ips[2], ips[3], addr.port)
        rep = "\x05\x00\x00\x01" + s
        # print repr(rep)
        self.transport_write(rep)
        self.sockv5.isverify = True


class ProxyFactory(protocol.Factory):
    """
    Factory for port forwarder.
    """
    protocol = ProxyServer
    def __init__(self, key):
        self.crypto = crypt.MyCrypto(key)
        # self.host = host
        # self.port = port
# help(log)
# print dir(log)

endpoints.serverFromString(reactor, "tcp:1234").listen(ProxyFactory("123456"))
reactor.run()


