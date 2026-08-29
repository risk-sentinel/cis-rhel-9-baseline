# encoding: UTF-8

control 'C-2.1.3' do
  title 'Ensure dhcp server services are not in use'
  desc  "
    The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses. There are two versions of the DHCP protocol `DHCPv4` and `DHCPv6`. At startup the server may be started for one or the other via the `-4` or `-6` arguments.

    Unless a system is specifically set up to act as a DHCP server, it is recommended that the `dhcp-server` package be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    The Dynamic Host Configuration Protocol (DHCP) is a service that allows machines to be dynamically assigned IP addresses. There are two versions of the DHCP protocol `DHCPv4` and `DHCPv6`. At startup the server may be started for one or the other via the `-4` or `-6` arguments.

    Unless a system is specifically set up to act as a DHCP server, it is recommended that the `dhcp-server` package be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify `dhcp-server` is not installed:

    ```
    # rpm -q dhcp-server

    package dhcp-server is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `dhcpd.service` and `dhcpd6.service` are not enabled:

    ```
    # systemctl is-enabled dhcpd.service dhcpd6.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `dhcpd.service` and `dhcpd6.service` are not active:

    ```
    # systemctl is-active dhcpd.service dhcpd6.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `dhcpd.service` and `dhcpd6.service` and remove `dhcp-server` package:

    ```
    # systemctl stop dhcpd.service dhcpd6.service
    # dnf remove dhcp-server
    ```

    - OR -

    - IF - the `dhcp-server` package is required as a dependency:

    Run the following commands to stop and mask `dhcpd.service` and `dhcpd6.service`:

    ```
    # systemctl stop dhcpd.service dhcpd6.service
    # systemctl mask dhcpd.service dhcpd6.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.3'
  tag cis_number:            '2.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('dhcpd') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end