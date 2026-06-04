# encoding: UTF-8

control 'C-4.3.1' do
  title 'Ensure nftables base chains exist'
  desc  "
    Chains are containers for rules. They exist in two kinds, base chains and regular chains. A base chain is an  entry  point  for packets from the networking stack, a regular chain may be used as jump target and is used for better rule organization.

    Note: - IF - `Firewalld` is in use, this recommendation can be skipped.

    If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through those chains will not be touched by nftables.
  "
  desc  'rationale', "
    Chains are containers for rules. They exist in two kinds, base chains and regular chains. A base chain is an  entry  point  for packets from the networking stack, a regular chain may be used as jump target and is used for better rule organization.

    Note: - IF - `Firewalld` is in use, this recommendation can be skipped.

    If a base chain doesn't exist with a hook for input, forward, and delete, packets that would flow through those chains will not be touched by nftables.
  "
  desc  'check', "
    - IF - `NFTables` utility is in use on your system:

    Run the following command to verify that base chains exist for the `INPUT` filter hook:
 
    ```
    # nft list ruleset | grep 'hook input'
    ```

    Output should include:

    ```
    type filter hook input
    ```

    Run the following command to verify that base chains exist for the `FORWARD` filter hook:
 
    ```
    # nft list ruleset | grep 'hook forward'
    ```

    Output should include:

    ```
    type filter hook forward
    ```

    Run the following command to verify that base chains exist for the `OUTPUT` filter hook:
 
    ```
    # nft list ruleset | grep 'hook output'
    ```

    Output should include:

    ```
    type filter hook output
    ```

    Note: When using FirewallD the base chains are installed by default
  "
  desc  'fix', "
    - IF - `NFTables` utility is in use on your system:

    Run the following command to create the base chains:

    ```
    # nft create chain inet { type filter hook <(input|forward|output)> priority 0 \\; }
    ```

    _Example:_
    ```
    # nft create chain inet filter input { type filter hook input priority 0 \\; }
    # nft create chain inet filter forward { type filter hook forward priority 0 \\; }
    # nft create chain inet filter output { type filter hook output priority 0 \\; }
    ```


    Note: use the `add` command if the `create` command returns an error due to the chain already existing.
  "
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.3.1'
  tag cis_number:            '4.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  applicable = !service('firewalld').running?
  impact(applicable ? 0.5 : 0.0)
  describe command(%q{nft list ruleset 2>/dev/null | grep -E 'hook input|hook forward|hook output'}) do
    its('stdout') { should match(/\S/) }
  end
  only_if('N/A unless nftables (standalone) is the active firewall (see 4.1.2)') { applicable }
end