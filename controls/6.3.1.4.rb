# encoding: UTF-8

control 'C-6.3.1.4' do
  title 'Ensure auditd service is enabled and active'
  desc  "
    Turn on the `auditd` daemon to record system events.

    The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
  "
  desc  'rationale', "
    Turn on the `auditd` daemon to record system events.

    The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
  "
  desc  'check', "
    Run the following command to verify `auditd`  is enabled:

    ```
    # systemctl is-enabled auditd | grep '^enabled'

    enabled
    ```

    Verify result is \"enabled\".

    Run the following command to verify `auditd` is active:

    ```
    # systemctl is-active auditd | grep '^active'

    active
    ```

    Verify result is active
  "
  desc  'fix', "
    Run the following commands to unmask, enable and start `auditd`:

    ```
    # systemctl unmask auditd
    # systemctl enable auditd
    # systemctl start auditd
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.3.1.4'
  tag cis_number:            '6.3.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('auditd') do
    it { should be_enabled }
    it { should be_running }
  end
end