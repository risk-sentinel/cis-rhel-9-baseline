# encoding: UTF-8

control 'C-2.1.5' do
  title 'Ensure dnsmasq services are not in use'
  desc  "
    `dnsmasq` is a lightweight tool that provides DNS caching, DNS forwarding and DHCP (Dynamic Host Configuration Protocol) services.

    Unless a system is specifically designated to act as a DNS caching, DNS forwarding and/or DHCP server, it is recommended that the package be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    `dnsmasq` is a lightweight tool that provides DNS caching, DNS forwarding and DHCP (Dynamic Host Configuration Protocol) services.

    Unless a system is specifically designated to act as a DNS caching, DNS forwarding and/or DHCP server, it is recommended that the package be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run one of the following commands to verify `dnsmasq` is not installed:

    ```
    # rpm -q dnsmasq

    package dnsmasq is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `dnsmasq.service` is not enabled:

    ```
    # systemctl is-enabled dnsmasq.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `dnsmasq.service` is not active:

    ```
    # systemctl is-active dnsmasq.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `dnsmasq.service` and remove `dnsmasq` package:

    ```
    # systemctl stop dnsmasq.service
    # dnf remove dnsmasq
    ```

    - OR -

    - IF - the `dnsmasq` package is required as a dependency:

    Run the following commands to stop and mask the `dnsmasq.service`:

    ```
    # systemctl stop dnsmasq.service
    # systemctl mask dnsmasq.service
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.5'
  tag cis_number:            '2.1.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020105r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure dnsmasq services are not in use' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-020105r1_rule.'
  end
end
