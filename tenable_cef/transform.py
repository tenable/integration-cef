import arrow, logging
from .pool import ThreadPool

def trunc(text, limit):
    '''
    Truncates a string to a given number of characters.  If a string extends
    beyond the limit, then truncate and add an ellipses after the truncation.

    Args:
        text (str): The string to truncate
        limit (int): The maximum limit that the string can be.

    Returns:
        str: The truncated string
    '''
    text = text.replace('|', '\\|').replace('=', '\\=')
    if len(text) >= limit:
        return '{}...'.format(text[:limit - 4])
    return text


class TioTransform:
    def __init__(self, tio, cef):
        self._log = logging.getLogger('{}.{}'.format(
            self.__module__, self.__class__.__name__))
        self.tio = tio
        self.cef = cef

    def _transform_vulnerability(self, vuln):
        '''
        Transforms a Tenable.io vulnerability into a CEF event
        '''
        asset = vuln.get('asset')
        plugin = vuln.get('plugin')
        self.cef.cef_send(
            plugin.get('id'),
            plugin.get('name'),
            vuln.get('severity'),
            dst=asset.get('ipv4'),
            dmac=asset.get('mac_address'),
            dhost=asset.get('hostname'),
            dport=vuln.get('port').get('port'),
            proto=vuln.get('port').get('protocol'),
            rt=arrow.get(vuln.get('last_found')).timestamp * 1000,
            cs1=trunc(vuln.get('output', 'None'), 1000),
            cs1Label='VulnerabilityOutput',
            cs2=trunc(plugin.get('description', 'None'), 1000),
            cs2Label='VulnerabilityDescription',
            cs3=trunc(plugin.get('solution', 'None'), 1000),
            cs3Label='VulnerabilitySolution',
            cs4=plugin.get('cvss_base_score'),
            cs4Label='CVSSBase core',
            cs5=' '.join(plugin.get('cve', [])),
            cs5Label='CVE',
            cs6=plugin.get('vpr', {}).get('score'),
            cs6Label='VPRScore',
        )

    def ingest(self, observed_since, threads=2, severity=None):
        '''
        Perform the ingestion

        Args:
            observed_since (int):
                The unix timestamp of the age threshhold.  Only vulnerabilities
                observed since this date will be imported.
            threads (int, optional):
                The number of concurrent threads to insert the data into SCC.
                If nothing is specified, the default is 2
        '''
        if not severity:
            severity = ['low', 'medium', 'high', 'critical']

        # Now we need to  transform the vulnerability data.  We will initiate an
        # export of the vulnerabilities from Tenable.io.  If the vulnerability
        # pertains to an Azure asset, then we will transform that finding and
        # send the finding in CEF
        vcounter = 0
        vulns = self.tio.exports.vulns(last_updated=observed_since,
            severity=severity, state=['open', 'reopened'])

        pool = ThreadPool(threads)
        for vuln in vulns:
            vcounter += 1
            pool.add_task(self._transform_vulnerability, vuln)
        pool.wait_completion()
        self._log.info('transformed and ingested {} vulns'.format(vcounter))