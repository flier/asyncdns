#!/usr/bin/env python
from __future__ import with_statement

import logging
import unittest

import time
import datetime

import dns.rcode
import dns.opcode

from asyncdns.timewheel import *
from asyncdns.pipeline import *

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

            for i in range(9):
                self.assertEquals([], slot.check())

            self.assertEquals([timer], slot.check())
            self.assertEquals([], slot.timers)

    def testWheel(self):
        wheel = TimeWheel()

        self.assertFalse(wheel.isTerminated())

        timer = wheel.create(None, 10)

        self.assertEquals(10, timer.expired)

        expired = int(time.time()+timer.expired)

        self.assert_(timer in wheel.slots[expired%len(wheel.slots)])

        for i in range(9):
            self.assertEquals([], wheel.check(expired))

        self.assertEquals([timer], wheel.check(expired))

    def testDispatcher(self):
        wheel = TimeWheel(task_pool_size=1)
        wheel.start()

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
        self.wheel.start()

        self.pipeline = Pipeline(self.wheel)
        self.pipeline.start()

    def tearDown(self):
        self.pipeline.close()
        self.wheel.terminate()

    def testLifecycle(self):
        self.assertFalse(self.pipeline.isTerminated())
        self.assertEquals(0, len(self.pipeline))

        r = self.pipeline.query("www.google.com.", expired=5)

        self.assertEqual(dns.rcode.NOERROR, r.rcode())
        self.assertEqual(dns.opcode.QUERY, r.opcode())

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    unittest.main()
