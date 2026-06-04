# encoding: UTF-8

control 'C-4.3.3' do
  title 'Ensure nftables default deny firewall policy'
  desc  "
    Base chain policy is the default verdict that will be applied to packets reaching the end of the chain.

    There are two policies: accept (Default) and drop.  If the policy is set to `accept`, the firewall will accept any packet that is not configured to be denied and the packet will continue traversing the network stack.

    It is easier to explicitly permit acceptable usage than to deny unacceptable usage.

    Note: 
    - - IF - `Firewalld` is in use, this recommendation can be skipped.
    - Changing firewall settings while connected over the network can result in being locked out of the system.
  "
  desc  'rationale', "
    Base chain policy is the default verdict that will be applied to packets reaching the end of the chain.

    There are two policies: accept (Default) and drop.  If the policy is set to `accept`, the firewall will accept any packet that is not configured to be denied and the packet will continue traversing the network stack.

    It is easier to explicitly permit acceptable usage than to deny unacceptable usage.

    Note: 
    - - IF - `Firewalld` is in use, this recommendation can be skipped.
    - Changing firewall settings while connected over the network can result in being locked out of the system.
  "
  desc  'check', "
    - IF - `NFTables` utility is in use on your system:

    Run the following commands and verify that base chains contain a policy of `DROP`. 

    ```
    # systemctl --quiet is-enabled nftables.service && nft list ruleset | grep 'hook input' | grep -v 'policy drop'
    ```
    Nothing should be returned
    ```
    # systemctl --quiet is-enabled nftables.service && nft list ruleset | grep 'hook forward' | grep -v 'policy drop'
    ```
    Nothing should be returned
  "
  desc  'fix', "
    - IF - `NFTables` utility is in use on your system:

    Run the following command for the base chains with the input, forward, and output hooks to implement a default DROP policy:

    ```
    # nft chain { policy drop \\; }
    ```

    _Example:_
    ```
    # nft chain inet filter input { policy drop \\; }
    # nft chain inet filter forward { policy drop \\; }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.3.3'
  tag cis_number:            '4.3.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040303r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure nftables default deny firewall policy' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-040303r1_rule.'
  end
end
