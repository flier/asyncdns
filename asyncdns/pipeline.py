#!/usr/bin/env python
from __future__ import with_statement

import sys
import logging
import socket
from errno import *
import asyncore
import threading

import traceback

import Queue

import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.message
import dns.resolver
import dns.exception

from timewheel import TimeWheel

class Pipeline(asyncore.dispatcher, threading.Thread):
    logger = logging.getLogger("asyncdns.pipeline")

    def __init__(self, wheel=None, proxy=None, start=True):
        asyncore.dispatcher.__init__(self)
        threading.Thread.__init__(self, name="asyncdns.pipeline")

        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)

        if proxy:
            proxy.wrap(self.socket)

        self.terminated = threading.Event()
        self.task_queue = Queue.Queue()

        self.pending_tasks_lock = threading.Lock()
        self.pending_tasks = {}

        self.wheel = wheel

        if self.wheel is None:
            self.wheel = TimeWheel()

        self.setDaemon(True)

        if start:
            self.start()

    def __len__(self):
        return self.queued + self.pending

    @property
    def queued(self):
        return self.task_queue.qsize()

    @property
    def pending(self):
        return sum([len(tasks) for tasks in self.pending_tasks.values()])

    @staticmethod
    def system_nameservers():
        return dns.resolver.get_default_resolver().nameservers

    def isTerminated(self):
        return self.terminated.isSet()

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        packet, nameserver = self.recvfrom(65535)

        if packet:
            try:
                response = dns.message.from_wire(packet)
            except dns.exception.FormError:
                self.logger.warn("drop invalid DNS packet from %s:%d", *nameserver)

                return

            with self.pending_tasks_lock:
                if nameserver not in self.pending_tasks:
                    self.logger.warn("drop unexpected DNS packet from %s:%d", *nameserver)

                    return

                tasks = self.pending_tasks[nameserver]

                for request in tasks.keys():
                    if request.is_response(response):
                        callback, timer = tasks[request]

                        del tasks[request]

                        timer.cancel()

                        try:
                            callback(nameserver, response)
                        except Exception, e:
                            self.logger.warn("fail to execute callback: %s", e)
                            self.logger.debug("exc: %s", traceback.format_exc())
                            self.logger.debug("res: %s", response)

    def writable(self):
        return not self.task_queue.empty()

    def handle_write(self):
        request, expired, callback, nameserver = self.task_queue.get_nowait()

        try:
            packet = request.to_wire()

            if self.sendto(packet, nameserver):
                with self.pending_tasks_lock:
                    tasks = self.pending_tasks.setdefault(nameserver, {})

                    def ontimeout():
                        del tasks[request]

                        try:
                            callback(nameserver, socket.timeout("dns query to %s was timeout after %d seconds" % (nameserver[0], expired)))
                        except Exception, e:
                            self.logger.warn("fail to execute callback: %s", e)
                            self.logger.debug("exc: %s", traceback.format_exc())
                            self.logger.debug("res: %s", request)

                    timer = self.wheel.create(ontimeout, expired)

                    tasks[request] = (callback, timer)
        except Exception, e:
            self.logger.warn("fail to send query, %s", e)

    def sendto(self, data, address):
        try:
            return self.socket.sendto(data, 0, address)
        except socket.error, why:
            if why[0] == EWOULDBLOCK:
                return 0
            else:
                self.logger.warn("fail to send packet, %s", why)

                raise

            return 0

    def recvfrom(self, bufize):
        try:
            return self.socket.recvfrom(65535)
        except socket.error, why:
            if why[0] in [EWOULDBLOCK, EAGAIN]:
                return None, None
            else:
                self.logger.warn("fail to receive packet, %s", why)

                raise

    def query(self, qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
              expired=30, callback=None, nameservers=None, port=53):
        if isinstance(qname, (str, unicode)):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if isinstance(rdclass, str):
            rdclass = dns.rdataclass.from_text(rdclass)

        if not qname.is_absolute():
            qname = qname.concatenate(dns.name.root)

        if nameservers is None:
            nameservers = self.system_nameservers()

        self.logger.info("query name servers %s for type %s and class %s record of domain %s in %d seconds",
                         ', '.join(nameservers),
                         dns.rdatatype.to_text(rdtype),
                         dns.rdataclass.to_text(rdclass),
                         qname, expired)

        request = dns.message.make_query(qname, rdtype, rdclass)

        found = None if callback else threading.Event()
        results_lock = threading.Lock()
        results = []

        def collect_result(nameserver, response):
            with results_lock:
                results.append((nameserver, response))

                if not isinstance(response, Exception) or \
                   len(results) == len(nameservers):
                    found.set()

        for nameserver in nameservers:
            self.task_queue.put_nowait((request, expired, callback or collect_result, (nameserver, port)))

        if callback is None:
            found.wait(expired)

            for nameserver, result in results:
                if not isinstance(result, Exception):
                    return nameserver, result

            raise results.pop()[1]

    def run(self):
        try:
            asyncore.loop(timeout=1, use_poll=True)
        except Exception, e:
            self.logger.warn("fail to run asyncdns pipeline, %s", e)

if __name__=='__main__':
    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    pipeline = Pipeline()

    def dump(nameserver, response):
        print nameserver, response

    for domain in sys.argv[1:]:
        if domain[0] != '-':
            pipeline.query(domain, callback=dump)

    pipeline.join()
