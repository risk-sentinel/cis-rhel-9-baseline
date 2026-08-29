# encoding: UTF-8

control 'C-2.3.1' do
  title 'Ensure time synchronization is in use'
  desc  "
    System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.

    Note: If another method for time synchronization is being used, this section may be skipped.

    Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations.
  "
  desc  'rationale', "
    System time should be synchronized between all systems in an environment. This is typically done by establishing an authoritative time server or set of servers and having all systems synchronize their clocks to them.

    Note: If another method for time synchronization is being used, this section may be skipped.

    Time synchronization is important to support time sensitive security mechanisms like Kerberos and also ensures log files have consistent time records across the enterprise, which aids in forensic investigations.
  "
  desc  'check', "
    Run the following commands to verify that `chrony` is installed:
    ```
    # rpm -q chrony

    chrony- ```
  "
  desc  'fix', "
    Run the following command to install `chrony`:

    ```
    # dnf install chrony
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 i 1', 'AU-8 a']
  tag nist_r4:               ['AC-2 i 1', 'AU-8 a']
  tag cci:                   ['CCI-002126', 'CCI-000159']
  tag cis_rid:               '2.3.1'
  tag cis_number:            '2.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('chrony') do
    it { should be_installed }
  end
end