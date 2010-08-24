#!/usr/bin/env python
from __future__ import with_statement

import time
import datetime
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

    def insert(self, timer):
        with self.lock:
            timer.slot = self

            self.timers.append(timer)

    def remove(self, timer):
        with self.lock:
            if timer in self.timers:
                self.timers.remove(timer)

    def check(self):
        fired = []

        with self.lock:
            for timer in self.timers:
                timer.expired -= 1

                if timer.expired <= 0:
                    self.timers.remove(timer)
                    fired.append(timer)

        return fired

class TimeWheel(object):
    logger = logging.getLogger("asyncdns.timewheel")

    class Dispatcher(threading.Thread):
        def __init__(self, terminated, task_queue):
            threading.Thread.__init__(self, name="asyncdns.dispatcher")

            self.setDaemon(True)
            self.start()

            self.terminated = terminated
            self.task_queue = task_queue

        def run(self):
            while not self.terminated.isSet():
                timer = self.task_queue.get()
                timer.call()
                self.task_queue.task_done()

    def __init__(self, slots=360, task_pool_size=None):
        self.slots = [TimeSlot() for i in range(slots)]
        self.terminated = threading.Event()

        if task_pool_size:
            self.task_queue = Queue.Queue()
            self.task_pool = [Dispatcher(self.terminated, self.task_queue) for i in task_pool_size]
        else:
            self.task_queue = None
            self.task_pool = []

    def create(self, callback, expired):
        timer = Timer(self, callback, expired)

        self.slots[timer.expired % len(self.slots)].insert(timer)

        return timer

    def check(self, ts):
        with self.slots[Timer.normalize(ts) % len(self.slots)] as slot:
            return slot.check()

    def terminate(self):
        self.terminated = True

    def run(self):
        latest = int(time.time())

        while not self.terminated.isSet():
            self.terminated.wait(1)

            timers = []

            for ts in range(latest, int(time.time())):
                timers.extend(self.check(ts))

            for timer in timers:
                if self.task_queue:
                    self.task_queue.put_nowait(timer)
                else:
                    timer.call()
