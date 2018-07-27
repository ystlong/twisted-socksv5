# -*- coding: utf-8 -*-
# @Author: ystlong
# @Date:   2018-07-22 15:44:56
# @Last Modified by:   ystlong
# @Last Modified time: 2018-07-28 01:24:01

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
        # print "recive data len: ", len(data)
        data = self.peer.factory.crypto.decrypt(data)
        self.peer.transport.write(data)

    def transport_write(self, data):
        data = self.peer.factory.crypto.encrypt(data)
        self.transport.write(data)

    def connectionMade(self):
        self.peer.setPeer(self)
        # print "xxxxxx"
        # Wire this and the peer transport together to enable
        # flow control (this stops connections from filling
        # this proxy memory when one side produces data at a
        # higher rate than the other can consume).
        self.transport.registerProducer(self.peer.transport, True)
        self.peer.transport.registerProducer(self.transport, True)

        # We're connected, everybody can read to their hearts content.
        self.peer.transport.resumeProducing()
        self.peer.client_ok()


class ProxyClientFactory(protocol.ClientFactory):

    protocol = ProxyClient

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
    client_started = False
    last_data = None

    def start_client(self):
        # Don't read anything from the connecting client until we have
        # somewhere to send it to.
        self.transport.pauseProducing()

        client = self.clientProtocolFactory()
        client.setServer(self)

        if self.reactor is None:
            # from twisted.internet import reactor
            self.reactor = reactor
        self.reactor.connectTCP(self.factory.host, self.factory.port, client)
        pass

    def client_ok(self):
        print "client ok,", self.transport.getHost()
        self.client_started = True
        if self.last_data != None:
            self.peer.transport_write(self.last_data)
            self.last_data = None

    def connectionMade(self):
        # self.start_client()
        pass        


    def dataReceived(self, data):
        if self.client_started == False:
            self.start_client()
            self.last_data = data
        else:
            # print "ssssss"
            # print data
            self.peer.transport_write(data)
        # print "========="

class ProxyFactory(protocol.Factory):
    """
    Factory for port forwarder.
    """

    protocol = ProxyServer

    def __init__(self, host, port, key):
        self.host = host
        self.port = port
        self.crypto = crypt.MyCrypto(key)



endpoints.serverFromString(reactor, "tcp:8080").listen(ProxyFactory("127.0.0.1", 1234, "123456"))
reactor.run()


