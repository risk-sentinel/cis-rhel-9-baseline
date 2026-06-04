# encoding: UTF-8

control 'C-4.1.1' do
  title 'Ensure nftables is installed'
  desc  "
    nftables provides a new in-kernel packet classification framework that is based on a network-specific Virtual Machine (VM) and a new nft userspace command line tool. 

    nftables reuses the existing Netfilter subsystems such as the existing hook infrastructure, the connection tracking system, NAT, userspace queuing and logging subsystem.

    nftables is a subsystem of the Linux kernel that can protect against threats originating from within a corporate network to include malicious mobile code and poorly configured software on a host.
  "
  desc  'rationale', "
    nftables provides a new in-kernel packet classification framework that is based on a network-specific Virtual Machine (VM) and a new nft userspace command line tool. 

    nftables reuses the existing Netfilter subsystems such as the existing hook infrastructure, the connection tracking system, NAT, userspace queuing and logging subsystem.

    nftables is a subsystem of the Linux kernel that can protect against threats originating from within a corporate network to include malicious mobile code and poorly configured software on a host.
  "
  desc  'check', "
    Run the following command to verify that `nftables` is installed:
    ```
    # rpm -q nftables

    nftables- ```
  "
  desc  'fix', "
    Run the following command to install `nftables`

    ```
    # dnf install nftables
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.1.1'
  tag cis_number:            '4.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure nftables is installed' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-040101r1_rule.'
  end
end
