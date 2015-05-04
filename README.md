# asyncdns
asyncdns is an asynchronous DNS query pipeline for Python, which could maintain massive concurrent DNS queries to several DNS servers.

Features
* **async pipeline**: an full asynchronous pipeline shared by thousands DNS queries with callback
* **socks 5 proxy**: support to send a DNS query through a socks 5 proxy server
* **query timeout**: trace thousands timers at the same time base on the time wheel algorithm
