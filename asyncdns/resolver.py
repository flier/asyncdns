#!/usr/bin/env python
import sys
import logging
import threading

import dns.rdatatype
import dns.rdataclass

from pipeline import Pipeline

class Resolver(Pipeline):
    logger = logging.getLogger("asyncdns.resolver")

    def __init__(self, wheel=None, start=True):
        Pipeline.__init__(self, wheel, start)

    def lookup(self, qname, rdtype, rdclass, expired=30,
               callback=None, nameservers=None, port=53):
        results = []
        finished = threading.Event()

        def onfinish(nameserver, response):
            if not isinstance(response, Exception):
                for rrset in response.answer:
                    if rdtype == dns.rdatatype.ANY and rrset.rdclass == rdclass:
                        results.extend([rdata for rdata in rrset])
                    elif rrset.rdtype == rdtype and rrset.rdclass == rdclass:
                        if rdtype in [dns.rdatatype.A, dns.rdatatype.AAAA]:
                            results.extend([rdata.address for rdata in rrset])
                        elif rdtype in [dns.rdatatype.MX]:
                            results.extend([(rdata.exchange, rdata.preference) for rdata in rrset])
                        elif rdtype in [dns.rdatatype.NS, dns.rdatatype.CNAME, dns.rdatatype.PTR]:
                            results.extend([rdata.target for rdata in rrset])
                        elif rdtype in [dns.rdatatype.SOA]:
                            results.extend([(rdata.mname, rdata.rname,
                                             rdata.serial, rdata.refresh,
                                             rdata.retry, rdata.expire,
                                             rdata.minimum) for rdata in rrset])
                        elif rdtype in [dns.rdatatype.WKS]:
                            results.extend([(rdata.address, rdata.protocol, rdata.bitmap) for rdata in rrset])
                        elif rdtype in [dns.rdatatype.SRV]:
                            results.extend([(rdata.target, rdata.port,
                                             rdata.priority, rdata.weight) for rdata in rrset])
                        elif rdtype in [dns.rdatatype.HINFO]:
                            results.extend([(rdata.cpu, rdata.os) for rdata in rrset])
                        elif rdtype in [dns.rdatatype.TXT]:
                            results.extend([rdata.strings for rdata in rrset])
                        elif rdtype in [dns.rdatatype.RP]:
                            results.extend([(rdata.mbox, rdata.txt) for rdata in rrset])
                        else:
                            results.extend([rdata for rdata in rrset])

                if callback:
                    try:
                        callback(qname, results)
                    except Exception, e:
                        self.logger.warn("fail to execute callback: %s", e)

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
