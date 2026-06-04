# encoding: UTF-8

control 'C-4.3.2' do
  title 'Ensure nftables established connections are configured'
  desc  "
    Configure the firewall rules for new outbound and established connections

    Note: - IF - `Firewalld` is in use, this recommendation can be skipped.

    If rules are not in place for established connections, all packets will be dropped by the default policy preventing network usage.
  "
  desc  'rationale', "
    Configure the firewall rules for new outbound and established connections

    Note: - IF - `Firewalld` is in use, this recommendation can be skipped.

    If rules are not in place for established connections, all packets will be dropped by the default policy preventing network usage.
  "
  desc  'check', "
    - IF - `NFTables` utility is in use on your system:

    Run the following commands and verify all rules for established incoming connections match site policy:

    ```
    # systemctl is-enabled nftables.service | grep -q 'enabled' && nft list ruleset | awk '/hook input/,/}/' | grep 'ct state'
    ```

    Output should be similar to:
    ```
    ip protocol tcp ct state established accept
    ip protocol udp ct state established accept
    ip protocol icmp ct state established accept
    ```
  "
  desc  'fix', "
    - IF - `NFTables` utility is in use on your system:

    Configure nftables in accordance with site policy. The following commands will implement a policy to allow all established connections:

    ```
    # systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol tcp ct state established accept
    # systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol udp ct state established accept
    # systemctl is-enabled nftables.service | grep -q 'enabled' && nft add rule inet filter input ip protocol icmp ct state established accept
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.3.2'
  tag cis_number:            '4.3.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040302r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure nftables established connections are configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-040302r1_rule.'
  end
end
