#!/usr/bin/env python
from __future__ import with_statement

import threading
import logging
import unittest

import time
import datetime

import dns.rcode
import dns.opcode

from asyncdns.timewheel import *
from asyncdns.pipeline import *
from asyncdns.proxy import *

class TestTimeWheel(unittest.TestCase):
    def testTimer(self):
        self.assertEquals(10, Timer.normalize(10))
        self.assertEquals(10, Timer.normalize(10.0))

        self.assertEquals(10, Timer.normalize(time.time()+10))

        self.assertEquals(10, Timer.normalize(datetime.timedelta(seconds=10)))
        self.assertEquals(10, Timer.normalize(datetime.datetime.now() + datetime.timedelta(seconds=10)))

        self.assertEquals("<Timer test expired in 10 seconds>", repr(Timer(None, 10, 'test')))

    def testSlot(self):
        with TimeSlot() as slot:
            self.assertEquals([], slot.timers)

            timer = Timer(None, 10)

            self.assertEquals(None, timer.slot)

            slot.insert(timer)

            self.assertEquals(slot, timer.slot)
            self.assertEquals(1, len(slot))
            self.assert_(timer in slot)
            self.assertEquals([timer], slot.timers)

            self.assert_(slot.remove(timer))
            self.assertFalse(slot.remove(timer))

            slot.insert(timer)

            for i in range(10):
                self.assertEquals([], slot.check())

            self.assertEquals([timer], slot.check())
            self.assertEquals([], slot.timers)

    def testWheel(self):
        wheel = TimeWheel()

        self.assertFalse(wheel.isTerminated())

        timer = wheel.create(None, len(wheel.slots)+10)

        self.assertEquals(1, timer.expired)

        expired = int(time.time()+10)

        self.assert_(timer in wheel.slots[expired%len(wheel.slots)])

        self.assertEquals([], wheel.check(expired))
        self.assertEquals([timer], wheel.check(expired))

    def testDispatcher(self):
        wheel = TimeWheel(task_pool_size=1)

        fired = threading.Event()

        self.assertFalse(fired.isSet())

        def callback():
            fired.set()

        timer = wheel.create(callback, 1)

        self.assertEquals(1, len(wheel))

        fired.wait(5)

        self.assert_(fired.isSet())
        self.assertEquals(0, len(wheel))

class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.wheel = TimeWheel()
        self.pipeline = Pipeline(self.wheel)

    def tearDown(self):
        self.pipeline.close()
        self.wheel.terminate()

    def testLifecycle(self):
        self.assertFalse(self.pipeline.isTerminated())

        finished = {}

        system_nameservers = self.pipeline.system_nameservers()

        for nameserver in system_nameservers:
            finished[nameserver] = threading.Event()

        def onfinish(nameserver, response):
            self.assertEqual(dns.rcode.NOERROR, response.rcode())
            self.assertEqual(dns.opcode.QUERY, response.opcode())
            self.assert_(len(response.answer) > 0)
            finished[nameserver[0]].set()

        self.pipeline.query("www.baidu.com.", callback=onfinish, expired=5)

        self.assertEquals(len(finished), len(self.pipeline))
        self.assertEquals(len(finished), self.pipeline.queued)
        self.assertEquals(0, self.pipeline.pending)

        [lock.wait(5) for lock in finished.values()]

        self.assertEquals(0, len(self.pipeline))

        self.assertEquals(0, len(self.pipeline))

        nameserver, response = self.pipeline.query("www.google.com.", expired=5)

        self.assertEqual(dns.rcode.NOERROR, response.rcode())
        self.assertEqual(dns.opcode.QUERY, response.opcode())
        self.assert_(len(response.answer) > 0)

        self.assert_(len(self.pipeline) < len(system_nameservers))

class TestSocksProxy(unittest.TestCase):
    def testProtocolConnect(self):
        proto = SocksProtocol(None)

        self.assertEqual(SocksProtocol.VER_SOCKS_5, proto.version)

        self.assertEqual("\x05\x02\x00\x02", proto.make_connect())
        self.assertEqual("\x05\x01\x02", proto.make_connect([SocksProtocol.METHOD_SIMPLE]))
        self.assertEqual("\x05\x01\x00", proto.make_connect([]))

        self.assertEqual(SocksProtocol.METHOD_NO_AUTH, proto.parse_connect("\x05\x00"))
        self.assertEqual(SocksProtocol.METHOD_GSSAPI, proto.parse_connect("\x05\x01"))
        self.assertEqual(SocksProtocol.METHOD_SIMPLE, proto.parse_connect("\x05\x02"))

        self.assertRaises(InvalidSocksVersion, proto.parse_connect, "\x04\x02")
        self.assertRaises(NoAcceptableAuthMethod, proto.parse_connect, "\x05\xff")

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    unittest.main()
