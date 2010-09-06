#!/usr/bin/env python
#
# The demo will analyze the DNS records of the top 1 million web sites
#
# Before run the demo:
#   1. Download and install mongodb and pymongo
#
#       http://www.mongodb.org/downloads
#
#       $apt-get install mongodb
#
#       http://api.mongodb.org/python/1.8.1%2B/installation.html
#
#       $easy_install -U pymongo
#
#   2. Download and unpack the top 1M sites from Alexa
#
#       $wget http://s3.amazonaws.com/alexa-static/top-1m.csv.zip
#       $unzip top-1m.csv.zip
#
from __future__ import with_statement

import sys
import os, os.path
import logging
import threading
import zipfile
import csv
import time
from datetime import datetime

try:
    from cStringIO import StringIO
except ImportError:
    from StringIO import StringIO

import dns.name
import dns.rdatatype

import pymongo
import asyncdns

DEFAULT_MONGO_HOST = "localhost"
DEFAULT_MONGO_PORT = 27017
DEFAULT_DATABASE_NAME = "alexa"
DEFAULT_DNS_SERVERS = asyncdns.Resolver.system_nameservers()
DEFAULT_DNS_TIMEOUT = 30
DEFAULT_CONCURRENCY = 20

def parse_cmdline():
    from optparse import OptionParser

    parser = OptionParser(usage="usage: %prog [options] <files>")

    parser.add_option("--mongo-host", dest="mongo_host", default=DEFAULT_MONGO_HOST,
                      metavar="HOST", help="mongodb host to connect to (default: %s)" % DEFAULT_MONGO_HOST)
    parser.add_option("--mongo-port", dest="mongo_port", default=27017, type="int",
                      metavar="PORT", help="mongodb port to connect to (default: %d)" % DEFAULT_MONGO_PORT)
    parser.add_option("--db-name", dest="db_name", default=DEFAULT_DATABASE_NAME,
                      metavar="NAME", help="mongodb database to open (default: %s)" % DEFAULT_DATABASE_NAME)

    parser.add_option("--dns-host", dest="dns_hosts", action="append", default=None,
                      metavar="HOST", help="DNS server to query (default: %s)" % ', '.join(DEFAULT_DNS_SERVERS))
    parser.add_option("-t", "--dns-timeout", dest="dns_timeout", default=DEFAULT_DNS_TIMEOUT, type="int",
                      metavar="NUM", help="DNS query timeout in seconds (default: %d)" % DEFAULT_DNS_TIMEOUT)

    parser.add_option("--force-update", dest="force_update", default=False, action="store_true",
                      help="force to update the exist domains")

    parser.add_option("-c", "--concurrency", default=DEFAULT_CONCURRENCY, type="int",
                      metavar="NUM", help="Number of multiple queries to make (default: %d)" % DEFAULT_CONCURRENCY)

    parser.add_option("-v", "--verbose", action="store_const",
                      const=logging.INFO, dest="log_level", default=logging.WARN)
    parser.add_option("-d", "--debug", action="store_const",
                      const=logging.DEBUG, dest="log_level")
    parser.add_option("--log-format", dest="log_format",
                      metavar="FMT", default="%(asctime)s %(levelname)s %(message)s")
    parser.add_option("--log-file", dest="log_file", metavar="FILE")

    opts, args = parser.parse_args()

    return opts, args

class Updater(object):
    logger = logging.getLogger("updater")

    def __init__(self, max_currency=20):
        self.lock = threading.Semaphore(max_currency)

    def connect(self, host, port, dbname):
        try:
            conn = pymongo.Connection(host, port)
        except pymongo.errors.AutoReconnect:
            self.logger.warn("fail to connect mongodb @ %s:%d", host, port)

            return None

        self.logger.info("connected to mongodb @ %s:%d [%s]", conn.host, conn.port,
                         ','.join(["%s: %s" % (k, v) for k, v in conn.server_info().items()]))

        self.db = conn[dbname]

        self.prepare(self.db)

        return conn

    def prepare(self, db):
        if 'domains' not in db.collection_names():
            self.logger.info("initialize the `domains` collection and indexes")

            db.domains.create_index([("domain", pymongo.ASCENDING)], unique=True)
            db.domains.create_index([("alexa", pymongo.ASCENDING)])
            db.domains.create_index([("ts", pymongo.DESCENDING)])

            db.domains.insert({
                "domain": ".",
                "ns" : [chr(ch) + '.root-servers.net' for ch in range(ord('a'), ord('m'))]
            })
        else:
            self.logger.info("found the `domains` collection")

            db.domains.ensure_index([("domain", pymongo.ASCENDING)], unique=True)
            db.domains.ensure_index([("alexa", pymongo.ASCENDING)])
            db.domains.ensure_index([("ts", pymongo.DESCENDING)])

            db.domains.update({"domain": "."}, {
                "$addToSet" : {
                    "ns" : {
                        "$each": [chr(ch) + '.root-servers.net' for ch in range(ord('a'), ord('m'))]
                    }
                }
            })

    def load(self, filename):
        self.logger.info("loading records from file %s", filename)

        if zipfile.is_zipfile(filename):
            zip = zipfile.ZipFile(filename, 'r')
            try:
                for name in zip.namelist():
                    for row in csv.reader(StringIO(zip.read(name))):
                        yield int(row[0]), row[1]
            finally:
                zip.close()
        else:
            with open(filename, 'r') as f:
                for row in csv.reader(f):
                    yield int(row[0]), row[1]

    def insert(self, records, update):
        count = updated = 0

        domains = []

        for alexa, domain in records:
            if update:
                record = self.db.domains.find_one({"domain": domain})

                if record:
                    record["alexa"] = alexa
                    record["ts"] = datetime.utcnow()

                    self.db.domains.save(record)

                    updated += 1

                    if updated % 1000 == 0:
                        self.logger.info("updated 1K records till %d", updated)

                    continue

            domains.append({
                "domain": domain,
                "alexa": alexa,
                "ts": datetime.utcnow()
            })

            count += 1

            if len(domains) == 10000:
                self.batch_insert(count, domains)

                domains = []

        self.batch_insert(count, domains)

    def batch_insert(self, pos, domains):
        if domains:
            start = time.clock()

            self.db.domains.insert(domains)

            self.logger.info("inserted 10K records till %sK in %f seconds",
                             pos/1000, time.clock() - start)

    def run(self, resolver, nameservers, timeout):
        self.queryLocalNameserver(resolver, nameservers, timeout)
        #self.queryAuthoritativeNameserver(resolver, timeout)

    def queryLocalNameserver(self, resolver, nameservers, timeout):
        cursor = self.db.domains.find({
            'domain': {'$exists': True},
            '$or': [
                { 'ip': {'$exists': False} },
                { 'ns': {'$exists': False} },
                { 'alias': {'$exists': False} },
            ]
        })

        self.logger.info("query %d domain from the local nameservers", cursor.count())

        if nameservers is None:
            nameservers = DEFAULT_DNS_SERVERS

        latch = asyncdns.CountDownLatch(cursor.count()*len(nameservers))

        def onfinish(nameserver, domain, results):
            self.lock.release()

            self.update(results)

            latch.countDown()

        for record in cursor:
            self.lock.acquire()

            try:
                resolver.lookupAllRecords(record['domain'], expired=timeout,
                                          callback=onfinish, nameservers=nameservers)
            except Exception, e:
                self.logger.warn("fail to query domain: %s, %s", record['domain'], e)

        latch.await()

    def queryAuthoritativeNameservers(self, resolver, timeout):
        self.logger.info("query")

        cursor = self.db.domains.find({
            'domain': {'$exists': True},
            'ns': {'$exists': False},
        })

        self.logger.info("query %d domain from the authoritative nameservers", cursor.count())

        latch = asyncdns.CountDownLatch(cursor.count())

        def onfinish():
            self.lock.release()

            latch.countDown()

        for record in cursor:
            self.lock.acquire()

            try:
                resolver.lookupScene(self.queryAuthoritativeNameserver(record['domain']),
                                     callback=onfinish)
            except Exception, e:
                self.logger.warn("fail to query domain: %s, %s", record['domain'], e)

        latch.await()

    @asyncdns.Scene()
    def queryAuthoritativeNameserver(self, domain):
        qname = dns.name.from_text(domain)

        domains = ['.'.join(qname[i:]) for i in range(len(qname))]

        nameservers = None

        while len(domains) > 1:
            domain = domains.pop()
            domain = '.' if domain == '' else domain.strip('.')

            record = self.db.domains.find({'domain': domain}, ['ns'])

            if record is None:
                nameserver, results = yield async.scene.Query(domain, dns.rdatatype.NS,
                                                              nameservers=nameservers)

                record = {
                    'domain': domain,
                    'ns' : results[domain][dns.rdatatype.NS]
                }

                record['_id'] = self.db.domains.insert(record)

            nameservers = record['ns']
            nameservers = nameservers[:min(3, len(nameservers))]

        yield async.scene.Finished

    DNS_FIELDNAME_MAPPING = {
        'A': 'ip',
        'AAAA': 'ipv6',
        'NS': 'ns',
        'CNAME': 'alias',
        'TXT': 'text',
    }

    def update(self, results):
        if isinstance(results, Exception):
            self.logger.warn("fail to query domain, %s", results)
            return

        for domain, records in results.items():
            self.logger.info("received result for %s", domain)

            if self.db.domains.find({"domain": domain}).count() == 0:
                self.db.domains.insert({
                    "domain": domain,
                    "ts": datetime.utcnow()
                })

            data = {}

            for rdtype, values in records.items():
                if rdtype in ['A', 'AAAA', 'NS', 'CNAME', 'TXT']:
                    data.setdefault("$addToSet", {})[self.DNS_FIELDNAME_MAPPING[rdtype]] = {
                        "$each": values
                    }
                elif rdtype == 'MX':
                    data.setdefault("$addToSet", {})['mail'] = {
                        "$each": [{
                            "exchange": exchange,
                            "preference": preference
                        } for exchange, preference in values]
                    }
                elif rdtype == 'SOA':
                    for mname, rname, serial, refresh, retry, expire, minimum in values:
                        data.setdefault("$set", {})["soa"] = {
                            "mname": mname,
                            "rname": rname,
                            "serial": serial,
                            "refresh": refresh,
                            "retry": retry,
                            "expire": expire,
                            "minimum": minimum
                        }
                elif rdtype == 'WKS':
                    data.setdefault("$addToSet", {})['service'] = {
                        "$each": [{
                            "address": address,
                            "protocol": protocol,
                            "bitmap": bitmap
                        } for address, protocol, bitmap in values]
                    }
                elif rdtype == 'SRV':
                    data.setdefault("$addToSet", {})['server'] = {
                        "$each": [{
                            "target": target,
                            "port": port,
                            "priority": priority,
                            "weight": weight
                        } for target, port, priority, weight in values]
                    }
                else:
                    self.logger.warn("drop domain %s unknown %s type: %s", domain, rdtype, values)

            self.db.domains.update({"domain": domain}, data)

if __name__=='__main__':
    opts, args = parse_cmdline()

    logging.basicConfig(level=opts.log_level,
                        format=opts.log_format,
                        filename=opts.log_file,
                        stream=sys.stdout)

    updater = Updater(opts.concurrency)

    if updater.connect(opts.mongo_host, opts.mongo_port, opts.db_name):
        for arg in args:
            if os.path.isfile(arg):
                updater.insert(updater.load(arg), opts.force_update)
            else:
                print "WARN: ignore invalid argument:", arg

        wheel = asyncdns.TimeWheel()
        resolver = asyncdns.Resolver(wheel)

        updater.run(resolver, opts.dns_hosts, opts.dns_timeout)
    else:
        print "ERROR: Fail to connect mongodb at %s:%d" % (opts.mongo_host, opts.mongo_port)
        print
        print "Please set the host and port with parameters, like"
        print
        print "     %s --mongo-host=<host> --mongo-port=<port> [options] <args>" % os.path.basename(sys.argv[0])
        print
        print "Or download and install mongodb from the offical site"
        print
        print "     http://www.mongodb.org/downloads"
