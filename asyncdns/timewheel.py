#!/usr/bin/env python
from __future__ import with_statement

import sys
import time
import datetime
import logging
import threading
import Queue

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

# Hashed and Hierarchical Timing Wheels: Efficient Data Structures for Implementing a Timer Facility (1996)
#
# http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.33.1519

class Timer(object):
    logger = logging.getLogger("asyncdns.timer")

    def __init__(self, callback, expired, name=None):
        self.slot = None
        self.callback = callback
        self.expired = expired
        self.name = name

    def __repr__(self):
        return "<Timer %s expired in %d seconds>" % (self.name or "#%d" % id(self), self.expired)

    def cancel(self):
        if self.slot:
            with self.slot:
                self.slot.remove(self)

    def call(self):
        if self.callback:
            try:
                self.callback()
            except Exception, e:
                self.logger.warn("fail to execute timer callback, %s", e)

    @staticmethod
    def normalize(expired):
        if isinstance(expired, datetime.datetime):
            expired = time.mktime(expired.timetuple())
        elif isinstance(expired, datetime.timedelta):
            expired = time.mktime((datetime.datetime.now() + expired).timetuple())

        expired = int(expired)
        now = int(time.time())

        if expired > now:
            expired -= now

        return expired

class TimeSlot(object):
    def __init__(self):
        self.lock = threading.Lock()
        self.timers = []

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.lock.release()

    def __len__(self):
        return len(self.timers)

    def __contains__(self, timer):
        return timer in self.timers

    def dump(self):
        return ', '.join([str(timer.expired) for timer in self.timers])

    def insert(self, timer):
        timer.slot = self

        self.timers.append(timer)

    def remove(self, timer):
        if timer in self.timers:
            self.timers.remove(timer)

            return True

        return False

    def check(self):
        fired = []

        for timer in self.timers:
            timer.expired -= 1

            if timer.expired < 0:
                fired.append(timer)

        for timer in fired:
            self.timers.remove(timer)

        return fired

class TimeWheel(threading.Thread):
    logger = logging.getLogger("asyncdns.timewheel")

    class Dispatcher(threading.Thread):
        def __init__(self, terminated, task_queue):
            threading.Thread.__init__(self, name="asyncdns.dispatcher")

            self.terminated = terminated
            self.task_queue = task_queue

            self.setDaemon(True)
            self.start()

        def run(self):
            while not self.terminated.isSet():
                timer = self.task_queue.get()
                timer.call()
                self.task_queue.task_done()

    def __init__(self, task_pool_size=0, slots=360, start=True):
        threading.Thread.__init__(self, name="asyncdns.timewheel")

        self.slots = [TimeSlot() for i in range(slots)]
        self.terminated = threading.Event()
        self.task_queue = Queue.Queue() if task_pool_size else None
        self.task_pool_size = task_pool_size

        self.setDaemon(True)

        if start:
            self.start()

    def __len__(self):
        return sum([len(slot) for slot in self.slots])

    def dump(self):
        out = StringIO()

        count = 0

        for slot in self.slots:
            if len(slot) > 0:
                print >>out, "Slot#%d %d: %s" % (count, len(slot), slot.dump())

            count += 1

        return out.getvalue()

    def create(self, callback, expired):
        expired = Timer.normalize(expired)
        timer = Timer(callback, expired/len(self.slots))

        with self.slots[int(time.time() + expired) % len(self.slots)] as slot:
            slot.insert(timer)

        return timer

    def check(self, ts=None):
        with self.slots[int(ts or time.time()) % len(self.slots)] as slot:
            return slot.check()

    def terminate(self):
        self.terminated.set()
        self.join()

    def isTerminated(self):
        return self.terminated.isSet()

    def run(self):
        latest = int(time.time())

        self.task_pool = [TimeWheel.Dispatcher(self.terminated, self.task_queue) for i in range(self.task_pool_size)]

        while not self.isTerminated():
            self.terminated.wait(1)

            if self.isTerminated():
                break

            current = int(time.time())

            timers = []

            for ts in range(latest, current):
                timers.extend(self.check(ts))

            latest = current

            for timer in timers:
                if self.task_queue:
                    self.task_queue.put_nowait(timer)
                else:
                    timer.call()
