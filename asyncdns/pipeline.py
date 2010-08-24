#!/usr/bin/env python
from __future__ import with_statement

import logging
import socket
import asyncore

class Pipeline(asyncore.dispatcher):
    logger = logging.getLogger("asyncdns.pipeline")

    def __init__(self):
        asyncore.dispatcher.__init__(self)

        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass

    def handle_connect(self):
        pass

    def handle_close(self):
        self.close()

    def handle_read(self):
        pass

    def writable(self):
        pass

    def handle_write(self):
        pass

    def query(self, domain, callback=None, nameservers=None):
        pass

    def run(self):
        try:
            asyncore.loop()
        except KeyboardInterrupt:
            pass
        except Exception, e:
            self.logger.warn("fail to run asyncdns pipeline, %s", e)

if __name__=='__main__':
    with Pipeline() as pipeline:
        pipeline.run()
