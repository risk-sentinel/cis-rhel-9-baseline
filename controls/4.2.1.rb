# encoding: UTF-8

control 'C-4.2.1' do
  title 'Ensure firewalld drops unnecessary services and ports'
  desc  "
    Services and ports can be accepted or explicitly rejected or dropped by a zone.

    For every zone, you can set a default behavior that handles incoming traffic that is not further specified. Such behavior is defined by setting the target of the zone. There are three options - default, ACCEPT, REJECT, and DROP.
    - ACCEPT - you accept all incoming packets except those disabled by a specific rule.
    - REJECT - you disable all incoming packets except those that you have allowed in specific rules and the source machine is informed about the rejection.
    - DROP - you disable all incoming packets except those that you have allowed in specific rules and no information sent to the source machine.

    Note: 
    - - IF - ```NFTables``` is being used, this recommendation can be skipped.
    - Allow port 22(ssh) needs to be updated to only allow systems requiring ssh connectivity to connect, as per site policy.

    To reduce the attack surface of a system, all services and ports should be blocked unless required
  "
  desc  'rationale', "
    Services and ports can be accepted or explicitly rejected or dropped by a zone.

    For every zone, you can set a default behavior that handles incoming traffic that is not further specified. Such behavior is defined by setting the target of the zone. There are three options - default, ACCEPT, REJECT, and DROP.
    - ACCEPT - you accept all incoming packets except those disabled by a specific rule.
    - REJECT - you disable all incoming packets except those that you have allowed in specific rules and the source machine is informed about the rejection.
    - DROP - you disable all incoming packets except those that you have allowed in specific rules and no information sent to the source machine.

    Note: 
    - - IF - ```NFTables``` is being used, this recommendation can be skipped.
    - Allow port 22(ssh) needs to be updated to only allow systems requiring ssh connectivity to connect, as per site policy.

    To reduce the attack surface of a system, all services and ports should be blocked unless required
  "
  desc  'check', "
    Run the following command and review output to ensure that listed services and ports follow site policy.  
    ```
    # systemctl is-enabled firewalld.service | grep -q 'enabled' && firewall-cmd --list-all --zone=\"$(firewall-cmd --list-all | awk '/\\(active\\)/ { print $1 }')\" | grep -P -- '^\\h*(services:|ports:)'
    ```
  "
  desc  'fix', "
    If Firewalld is in use on the system:

    Run the following command to remove an unnecessary service:

    ```
    # firewall-cmd --remove-service= ```

    _Example:_
    ```
    # firewall-cmd --remove-service=cockpit
    ```

    Run the following command to remove an unnecessary port:

    ```
    # firewall-cmd --remove-port= / ```

    _Example:_
    ```
    # firewall-cmd --remove-port=25/tcp
    ```

    Run the following command to make new settings persistent:
    ```
    # firewall-cmd --runtime-to-permanent
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.2.1'
  tag cis_number:            '4.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false
  tag attestation_category:  'operational'

  impact 0.5
  describe 'firewalld drops unnecessary services/ports (4.2.1)' do
    skip 'operational: the set of permitted services/ports is consumer workload policy; operator attests the allowed list against the service inventory (verified network-listening surface is covered by 2.1.22).'
  end
end