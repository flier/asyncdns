#!/usr/bin/env python
from __future__ import with_statement

import threading

class CountDownLatch(object):
    def __init__(self, count=1):
        self.count = count
        self.lock = threading.Condition()

    def countDown(self):
        with self.lock:
            self.count -= 1

            if self.count <= 0:
                self.lock.notifyAll()

    def await(self):
        with self.lock:
            while self.count > 0:
                self.lock.wait()

class ResultCollector(dict):
    def __init__(self, count):
        self.latch = CountDownLatch(count)

    def onfinish(self, nameserver, qname, response):
        if isinstance(response, Exception):
            self.setdefault('errors', []).append((nameserver, qname, response))
        else:
            self.setdefault(qname, {}).setdefault(nameserver, []).append(response)

        self.latch.countDown()

    def await(self):
        self.latch.await()

