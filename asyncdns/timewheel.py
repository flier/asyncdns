#!/usr/bin/env python
from __future__ import with_statement

import sys
import time
import datetime
import logging
import threading
import Queue

class Timer(object):
    logger = logging.getLogger("asyncdns.timer")

    def __init__(self, callback, expired):
        self.slot = None
        self.callback = callback
        self.expired = self.normalize(expired)

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

    def cancel(self):
        if self.slot:
            with self.slot:
                self.slot.remove(self)

    def call(self):
        try:
            self.callback()
        except Exception, e:
            self.logger.warn("fail to execute timer callback, %s", e)

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

            if timer.expired <= 0:
                self.timers.remove(timer)
                fired.append(timer)

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

    def __init__(self, task_pool_size=0, slots=360):
        threading.Thread.__init__(self, name="asyncdns.timewheel")

        self.slots = [TimeSlot() for i in range(slots)]
        self.terminated = threading.Event()
        self.task_queue = Queue.Queue() if task_pool_size else None
        self.task_pool_size = task_pool_size

        self.setDaemon(True)

    def __len__(self):
        return sum([len(slot) for slot in self.slots])

    def create(self, callback, expired):
        timer = Timer(callback, expired)

        with self.slots[int(time.time() + timer.expired) % len(self.slots)] as slot:
            slot.insert(timer)

        return timer

    def check(self, ts=None):
        with self.slots[int(ts or time.time()) % len(self.slots)] as slot:
            return slot.check()

    def terminate(self):
        self.terminated.set()

    def isTerminated(self):
        return self.terminated.isSet()

    def run(self):
        latest = int(time.time())

        self.task_pool = [TimeWheel.Dispatcher(self.terminated, self.task_queue) for i in range(self.task_pool_size)]

        while not self.isTerminated():
            self.terminated.wait(1)

            timers = []

            current = int(time.time())

            for ts in range(latest, current):
                timers.extend(self.check(ts))

            latest = current

            for timer in timers:
                if self.task_queue:
                    self.task_queue.put_nowait(timer)
                else:
                    timer.call()
