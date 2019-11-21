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
            cs1=trunc(vuln.get('output'), 4000),
            cs1Label='Vulnerability Output',
            cs2=trunc(plugin.get('description'), 4000),
            cs2Label='Vulnerability Description',
            cs3=trunc(plugin.get('solution'), 4000),
            cs3Label='Vulnerability Solution',
            cs4=plugin.get('cvss_base_score'),
            cs4Label='CVSS Base Score',
            cs5=' '.join(plugin.get('cve', [])),
            cs5Label='CVE',
        )

    def ingest(self, observed_since, threads=2, sources=None, severity=None):
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
        # The first thing that we need to do is perform the asset resource
        # generation.  We will export all of the assets that have data from the
        # Azure connector and process that information to build the cache that
        # we will need for the vuln ingestion.
        if sources:
            self._log.info('collecting asset records')
            assets = self.tio.exports.assets(sources=['Azure'],
                updated_at=observed_since)
            self._assets = list()
            for asset in assets:
                self._assets.append(asset.get('id'))
            self._log.info('discovered {} {} assets'.format(
                len(self._assets), ','.join(sources)))

        # Now we need to  transform the vulnerability data.  We will initiate an
        # export of the vulnerabilities from Tenable.io.  If the vulnerability
        # pertains to an Azure asset, then we will transform that finding and
        # send the finding in CEF
        vcounter = 0
        vulns = self.tio.exports.vulns(last_updated=observed_since,
            severity=severity, state=['open', 'reopened'])

        pool = ThreadPool(threads)
        for vuln in vulns:
            if ((sources and vuln.get('asset').get('uuid') in self._assets)
              or not sources):
                vcounter += 1
                pool.add_task(self._transform_vulnerability, vuln)
        pool.wait_completion()
        self._log.info('transformed and ingested {} vulns'.format(vcounter))