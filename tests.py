#!/usr/bin/env python
import logging
import unittest

import asyncdns
from asyncdns.timewheel import *

class TestTimeWheel(unittest.TestCase):
    def testTimer(self):
       pass

    def testSlot(self):
        pass

    def testWheel(self):
        pass

    def testDispatcher(self):
        pass

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    unittest.main()
