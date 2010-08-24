#!/usr/bin/env python
from __future__ import with_statement

import logging
import unittest

import time
import datetime

import asyncdns
from asyncdns.timewheel import *

class TestTimeWheel(unittest.TestCase):
    def testTimer(self):
       self.assertEquals(10, Timer.normalize(10))
       self.assertEquals(10, Timer.normalize(10.0))

       self.assertEquals(10, Timer.normalize(time.time()+10))

       self.assertEquals(10, Timer.normalize(datetime.timedelta(seconds=10)))
       self.assertEquals(10, Timer.normalize(datetime.datetime.now() + datetime.timedelta(seconds=10)))

    def testSlot(self):
        with TimeSlot() as slot:
            self.assertEquals([], slot.timers)

            timer = Timer(None, 10)

            self.assertEquals(None, timer.slot)

            slot.insert(timer)

            self.assertEquals(slot, timer.slot)
            self.assertEquals([timer], slot.timers)

            self.assert_(slot.remove(timer))
            self.assertFalse(slot.remove(timer))

            slot.insert(timer)

            for i in range(9):
                self.assertEquals([], slot.check())

            self.assertEquals([timer], slot.check())
            self.assertEquals([], slot.timers)

    def testWheel(self):
        pass

    def testDispatcher(self):
        pass

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    unittest.main()
