# encoding: UTF-8

control 'C-2.2.5' do
  title 'Ensure tftp client is not installed'
  desc  "
    Trivial File Transfer Protocol (TFTP) is a simple protocol for exchanging files between two TCP/IP machines. TFTP servers allow connections from a TFTP Client for sending and receiving files.

    TFTP does not have built-in encryption, access control or authentication. This makes it very easy for an attacker to exploit TFTP to gain access to files
  "
  desc  'rationale', "
    Trivial File Transfer Protocol (TFTP) is a simple protocol for exchanging files between two TCP/IP machines. TFTP servers allow connections from a TFTP Client for sending and receiving files.

    TFTP does not have built-in encryption, access control or authentication. This makes it very easy for an attacker to exploit TFTP to gain access to files
  "
  desc  'check', "
    Run the following command to verify `tftp` is not installed:

    ```
    # rpm -q tftp

    package tftp is not installed
    ```
  "
  desc  'fix', "
    Run the following command to remove `tftp`:

    ```
    # dnf remove tftp
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.2.5'
  tag cis_number:            '2.2.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020205r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe package('tftp') do
    it { should_not be_installed }
  end
end