import logging, socket
from . import __version__

class CEFSender:
    _cef_version = 0
    _vendor = 'Tenable'
    _product = 'Tenable.io'
    _build = __version__

    def __init__(self, address, port):
        self._log = logging.getLogger('{}.{}'.format(
            self.__module__, self.__class__.__name__))
        self.address = address
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def close(self):
        '''
        Closes the socket
        '''
        self.sock.close()

    def raw_send(self, msg):
        '''
        Send the message
        '''
        self._log.debug('SENDING: {}'.format(msg))
        self.sock.sendto(bytes(msg, 'utf-8'), (self.address, self.port))

    def cef_send(self, id, name, severity, **attrs):
        '''
        Send the event in a CEF format
        '''

        # A simple severity table for converting the Tenable severity ratings
        # into the CEF accepted format.
        sevmap = {
            'low': 'Low',
            'medium': 'Medium',
            'high': 'High',
            'Critical': 'Very-High'
        }

        # Format the data into the expected format and then pass the event to
        # the raw_send method.
        self.raw_send('|'.join([
            'CEF:{}'.format(self._cef_version),
            self._vendor,
            self._product,
            self._build,
            str(id),
            name.replace('|', '\\|'),
            sevmap[severity],
            ' '.join(['{}={}'.format(str(k), str(v).replace('\n', '\\n'))
                for k, v in attrs.items()])
        ]))