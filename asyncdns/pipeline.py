#!/usr/bin/env python
from __future__ import with_statement

import sys
import logging
import socket
import asyncore
import threading

import Queue

import dns.name
import dns.rdatatype
import dns.rdataclass
import dns.message
import dns.resolver

class Pipeline(asyncore.dispatcher, threading.Thread):
    logger = logging.getLogger("asyncdns.pipeline")

    def __init__(self, wheel):
        asyncore.dispatcher.__init__(self)
        threading.Thread.__init__(self, name="asyncdns.pipeline")

        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)

        self.terminated = threading.Event()
        self.task_queue = Queue.Queue()

        self.pending_tasks_lock = threading.Lock()
        self.pending_tasks = {}

        self.wheel = wheel

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        packet, nameserver = self.recvfrom(65535)
        response = dns.message.from_wire(packet)

        callback = None

        with self.pending_tasks_lock:
            tasks = self.pending_tasks[nameserver]

            for request in tasks.keys():
                if request.is_response(response):
                    callback, timer = tasks[request]

        timer.cancel()
        callback(nameserver, response)

    def writable(self):
        return not self.task_queue.empty()

    def handle_write(self):
        request, expired, callback, nameserver = self.task_queue.get_nowait()
        try:
            packet = request.to_wire()

            if self.sendto(packet, nameserver):
                with self.pending_tasks_lock:
                    tasks = self.pending_tasks.setdefault(nameserver, {})

                    def timeout():
                        del tasks[request]

                        callback(nameserver, socket.timeout())

                    timer = self.wheel.create(timeout, expired)

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
                raise
            return 0

    def query(self, qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
              expired=30, callback=None, nameservers=None, port=53):
        if isinstance(qname, (str, unicode)):
            qname = dns.name.from_text(qname, None)
        if isinstance(rdtype, str):
            rdtype = dns.rdatatype.from_text(rdtype)
        if isinstance(rdclass, str):
            rdclass = dns.rdataclass.from_text(rdclass)

        if nameservers is None:
            nameservers = dns.resolver.get_default_resolver().nameservers

        self.logger.info("query name servers %s for type %s and class %s record of domain %s in %d seconds",
                         ', '.join(nameservers),
                         dns.rdatatype.to_text(rdtype),
                         dns.rdataclass.to_text(rdclass),
                         qname, expired)

        request = dns.message.make_query(qname, rdtype, rdclass)

        for nameserver in nameservers:
            self.task_queue.put_nowait((request, expired, callback, (nameserver, port)))

    def run(self):
        try:
            asyncore.loop()
        except KeyboardInterrupt:
            pass
        except Exception, e:
            self.logger.warn("fail to run asyncdns pipeline, %s", e)

if __name__=='__main__':
    from timewheel import TimeWheel

    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    pipeline = Pipeline(TimeWheel())

    def dump(nameserver, response):
        print nameserver, response

    for domain in sys.argv[1:]:
        if domain[0] != '-':
            pipeline.query(domain, callback=dump)

    pipeline.start()
    pipeline.join()
