import mock

from tests.unit import utils

from plugins.maas.pyparts import (
    general,
)

SYSTEMD_UNITS = """
UNIT                                                                                             LOAD   ACTIVE SUB       DESCRIPTION 
maas-dhcpd.service                                                                               loaded active running   MAAS instance of ISC DHCP server for IPv4                                    
maas-http.service                                                                                loaded active running   MAAS HTTP server and reverse proxy server                                    
maas-proxy.service                                                                               loaded active running   MAAS Proxy                                                                   
maas-rackd.service                                                                               loaded active running   MAAS Rack Controller                                                         
maas-regiond.service                                                                             loaded active running   MAAS Region Controller                                                       
maas-syslog.service                                                                              loaded active running   MAAS Syslog Service
  corosync.service                                                                                 loaded active running   Corosync Cluster Engine                                                      
  pacemaker.service                                                                                loaded active running   Pacemaker High Availability Cluster Manager
"""  # noqa

SYSTEMD_UNIT_FILES = """
UNIT FILE                              STATE 
maas-dhcpd.service                     enabled        
maas-dhcpd6.service                    enabled        
maas-http.service                      enabled        
maas-proxy.service                     enabled        
maas-rackd.service                     enabled        
maas-regiond.service                   enabled        
maas-syslog.service                    enabled
postgresql.service                     disabled       
postgresql@.service                    disabled  
pacemaker.service                      enabled
corosync.service                      enabled
"""  # noqa

MAAS_DPKG = """
ii  maas-cli                               2.7.3-8291-g.384e521e6         all          MAAS client and command-line interface
ii  maas-common                            2.7.3-8291-g.384e521e6         all          MAAS server common files
ii  maas-dhcp                              2.7.3-8291-g.384e521e6         all          MAAS DHCP server
ii  maas-proxy                             2.7.3-8291-g.384e521e6         all          MAAS Caching Proxy
ii  maas-rack-controller                   2.7.3-8291-g.384e521e6         all          Rack Controller for MAAS
ii  maas-region-api                        2.7.3-8291-g.384e521e6         all          Region controller API service for MAAS
ii  maas-region-controller                 2.7.3-8291-g.384e521e6         all          Region Controller for MAAS
ii  python3-django-maas                    2.7.3-8291-g.384e521e6         all          MAAS server Django web framework (Python 3)
ii  python3-libmaas                        0.6.1-6-g91e96e9-dirty~bionic-0ubuntu1          all          MAAS asyncio client library (Python 3)
ii  python3-maas-client                    2.7.3-8291-g.384e521e6         all          MAAS python API client (Python 3)
ii  python3-maas-provisioningserver        2.7.3-8291-g.384e521e6         all          MAAS server provisioning libraries (Python 3)
"""  # noqa


class TestMAASGeneral(utils.BaseTestCase):

    @mock.patch('core.checks.CLIHelper')
    def test_install(self, mock_helper):
        mock_helper.return_value = mock.MagicMock()
        mock_helper.return_value.dpkg_l.return_value = \
            MAAS_DPKG.splitlines(keepends=True)
        inst = general.MAASInstallChecks()
        inst()
        expected = {'dpkg': ['maas-cli 2.7.3-8291-g.384e521e6',
                             'maas-common 2.7.3-8291-g.384e521e6',
                             'maas-dhcp 2.7.3-8291-g.384e521e6',
                             'maas-proxy 2.7.3-8291-g.384e521e6',
                             'maas-rack-controller 2.7.3-8291-g.384e521e6',
                             'maas-region-api 2.7.3-8291-g.384e521e6',
                             'maas-region-controller 2.7.3-8291-g.384e521e6']}
        self.assertEqual(inst.output, expected)

    @mock.patch('core.checks.CLIHelper')
    def test_services(self, mock_helper):
        with mock.patch.object(general.maas.MAASServiceChecksBase,
                               'maas_installed', lambda: True):
            mock_helper.return_value = mock.MagicMock()
            mock_helper.return_value.systemctl_list_unit_files.return_value = \
                SYSTEMD_UNIT_FILES.splitlines(keepends=True)
            mock_helper.return_value.systemctl_list_units.return_value = \
                SYSTEMD_UNITS.splitlines(keepends=True)
            expected = {'services': {
                            'ps': [],
                            'systemd': {'enabled': [
                                            'corosync',
                                            'maas-dhcpd',
                                            'maas-dhcpd6',
                                            'maas-http',
                                            'maas-proxy',
                                            'maas-rackd',
                                            'maas-regiond',
                                            'maas-syslog',
                                            'pacemaker'],
                                        'disabled': [
                                            'postgresql',
                                            ]}}}
            inst = general.MAASServiceChecks()
            inst()
            self.assertEqual(inst.output, expected)
