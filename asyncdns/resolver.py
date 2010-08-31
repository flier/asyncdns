#!/usr/bin/env python
import sys
import logging
import threading

import traceback

import dns.rdatatype
import dns.rdataclass

from pipeline import Pipeline

def normalize(s):
    for encoding in ['utf-8', 'latin1', 'cp1252', 'gbk']:
        try:
            return s.decode(encoding).encode('utf-8')
        except UnicodeDecodeError:
            pass

    return s.decode('utf-8', 'ignore').encode('utf-8')

class Resolver(Pipeline):
    logger = logging.getLogger("asyncdns.resolver")

    def __init__(self, wheel=None, proxy=None, start=True):
        Pipeline.__init__(self, wheel, proxy, start)

    @staticmethod
    def _extract_value(rrset):
        if rrset.rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
            return [rdata.address for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.MX]:
            return [(str(rdata.exchange), rdata.preference) for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.NS, dns.rdatatype.CNAME, dns.rdatatype.PTR]:
            return [str(rdata.target) for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.SOA]:
            return [(str(rdata.mname), str(rdata.rname),
                     rdata.serial, rdata.refresh,
                     rdata.retry, rdata.expire,
                     rdata.minimum) for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.WKS]:
            return [(rdata.address, rdata.protocol, rdata.bitmap) for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.SRV]:
            return [(str(rdata.target), rdata.port,
                     rdata.priority, rdata.weight) for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.HINFO]:
            return [(rdata.cpu, rdata.os) for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.TXT]:
            return [[normalize(s) for s in rdata.strings] for rdata in rrset]
        elif rrset.rdtype in [dns.rdatatype.RP]:
            return [(rdata.mbox, rdata.txt) for rdata in rrset]
        else:
            return [rdata for rdata in rrset]

    def _execute_callback(self, callback, nameserver, qname, response):
        try:
            callback(nameserver, qname, response)
        except Exception, e:
            self.logger.warn("fail to execute callback for domain %s: %s", qname, e)
            self.logger.debug("exc: %s", traceback.format_exc())
            self.logger.debug("res: %s", response)

    def lookup(self, qname, rdtype, rdclass, expired=30,
               callback=None, nameservers=None, port=53):
        results = {}
        finished = None if callback else threading.Event()

        def onfinish(nameserver, response):
            onerror = isinstance(response, Exception)

            if not onerror:
                for rrset in response.answer:
                    rdtypename = dns.rdatatype.to_text(rrset.rdtype)

                    results.setdefault(rdtypename, []).extend(Resolver._extract_value(rrset))

            if callback:
                self._execute_callback(callback, nameserver, qname, response if onerror else results)
            else:
                finished.set()

        self.query(qname, rdtype, rdclass, expired, onfinish, nameservers, port)

        if callback is None:
            finished.wait(expired)

            return results

    def lookupAddress(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.A, dns.rdataclass.IN, *args, **kwds)

    def lookupIPV6Address(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.AAAA, dns.rdataclass.IN, *args, **kwds)

    def lookupMailExchange(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.MX, dns.rdataclass.IN, *args, **kwds)

    def lookupNameservers(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.NS, dns.rdataclass.IN, *args, **kwds)

    def lookupCanonicalName(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.CNAME, dns.rdataclass.IN, *args, **kwds)

    def lookupPointer(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.PTR, dns.rdataclass.IN, *args, **kwds)

    def lookupAuthority(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.SOA, dns.rdataclass.IN, *args, **kwds)

    def lookupWellKnownServices(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.WKS, dns.rdataclass.IN, *args, **kwds)

    def lookupService(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.SRV, dns.rdataclass.IN, *args, **kwds)

    def lookupHostInfo(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.HINFO, dns.rdataclass.IN, *args, **kwds)

    def lookupText(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.TXT, dns.rdataclass.IN, *args, **kwds)

    def lookupResponsibility(self, qname, *args, **kwds):
        return self.lookup(qname, dns.rdatatype.RP, dns.rdataclass.IN, *args, **kwds)

    def lookupAllRecords(self, qname, *args, **kwds):
          return self.lookup(qname, dns.rdatatype.ANY, dns.rdataclass.IN, *args, **kwds)

if __name__=='__main__':
    from timewheel import TimeWheel

    logging.basicConfig(level=logging.DEBUG if "-v" in sys.argv else logging.WARN,
                        format='%(asctime)s %(levelname)s %(message)s')

    resolver = Resolver()

    for domain in sys.argv[1:]:
        if domain[0] != '-':
            print domain, resolver.lookupAddress(domain)
