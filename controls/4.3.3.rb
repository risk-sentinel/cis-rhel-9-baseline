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
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.3.3'
  tag cis_number:            '4.3.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040303r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # network_firewall axis: the default-deny ingress objective routes to where it is
  # enforced. cloud_sg => assert the SG default-deny posture; both => assert host nftables
  # default-drop AND the SG (defense-in-depth); host_nftables (strict default) => the
  # original host nftables assertion unchanged.
  if firewall_posture == 'cloud_sg'
    sg = aws_security_group_posture
    if sg.available?
      impact 0.5
      describe sg do
        it { should be_default_deny }
      end
    else
      impact 0.5
      describe 'SG ingress default-deny (live read unavailable)' do
        skip "network_firewall=cloud_sg but SG posture could not be read live (#{sg.error}); SAF attestation supplies evidence."
      end
    end
  elsif fw_both?
    impact 0.5
    describe command(%q{nft list ruleset 2>/dev/null | grep -E 'type filter hook (input|forward|output).*policy drop'}) do
      its('stdout') { should match(/\S/) }
    end
    sg = aws_security_group_posture
    if sg.available?
      describe sg do
        it { should be_default_deny }
      end
    else
      describe 'SG ingress default-deny (live read unavailable)' do
        skip "network_firewall=both but SG posture could not be read live (#{sg.error}); SAF attestation supplies evidence."
      end
    end
  else
    applicable = !service('firewalld').running?
    impact 0.5
    impact 0.0 unless applicable
    describe command(%q{nft list ruleset 2>/dev/null | grep -E 'type filter hook (input|forward|output).*policy drop'}) do
      its('stdout') { should match(/\S/) }
    end
    only_if('N/A unless nftables (standalone) is the active firewall (see 4.1.2)') { applicable }
  end
end