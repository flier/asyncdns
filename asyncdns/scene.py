#!/usr/bin/env python

import dns.name
import dns.rdatatype
import dns.rdataclass

class Query(object):
    def __init__(self, qname, rdtype=dns.rdatatype.A, rdclass=dns.rdataclass.IN,
                 nameservers=None, port=53):
        self.qname = qname
        self.rdtype = rdtype
        self.rdclass = rdclass
        self.nameservers = nameservers
        self.port = port

class Result(object):
    def __init__(self, result=None):
        self.result = result

Finished = Result()

class Scene(object):
    def __init__(self):
        pass

    def __call__(self, func):
        pass
