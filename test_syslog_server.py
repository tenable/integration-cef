#!/usr/bin/env python
import logging
from socketserver import UDPServer, BaseRequestHandler

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s')

class SyslogUDPHandler(BaseRequestHandler):

	def handle(self):
		data = bytes.decode(self.request[0].strip())
		socket = self.request[1]
		print( "%s : " % self.client_address[0], str(data))
		logging.info(str(data))

if __name__ == "__main__":
	try:
		server = UDPServer(('0.0.0.0',514), SyslogUDPHandler)
		server.serve_forever(poll_interval=0.5)
	except (IOError, SystemExit):
		raise
	except KeyboardInterrupt:
		print ("Crtl+C Pressed. Shutting down.")