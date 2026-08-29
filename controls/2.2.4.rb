# encoding: UTF-8

control 'C-2.2.4' do
  title 'Ensure telnet client is not installed'
  desc  "
    The `telnet` package contains the `telnet` client, which allows users to start connections to other systems via the telnet protocol.

    The `telnet` protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The `ssh` package provides an encrypted session and stronger security and is included in most Linux distributions.
  "
  desc  'rationale', "
    The `telnet` package contains the `telnet` client, which allows users to start connections to other systems via the telnet protocol.

    The `telnet` protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow an unauthorized user to steal credentials. The `ssh` package provides an encrypted session and stronger security and is included in most Linux distributions.
  "
  desc  'check', "
    Run the following command to verify that the `telnet` package is not installed:

    ```
    # rpm -q telnet

    package telnet is not installed
    ```
  "
  desc  'fix', "
    Run the following command to remove the `telnet` package:

    ```
    # dnf remove telnet
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT']
  tag nist_r4:               ['CM-7 a']
  tag cci:                   ['CCI-000381']
  tag cis_rid:               '2.2.4'
  tag cis_number:            '2.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('telnet') do
    it { should_not be_installed }
  end
end