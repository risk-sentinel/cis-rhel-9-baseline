# encoding: UTF-8

control 'C-6.3.2.1' do
  title 'Ensure audit log storage size is configured'
  desc  "
    Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.

    It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost.
  "
  desc  'rationale', "
    Configure the maximum size of the audit log file. Once the log reaches the maximum size, it will be rotated and a new log file will be started.

    It is important that an appropriate size is determined for log files so that they do not impact the system and audit data is not lost.
  "
  desc  'check', "
    Run the following command and ensure output is in compliance with site policy:

    ```
    # grep -Po -- '^\\h*max_log_file\\h*=\\h*\\d+\\b' /etc/audit/auditd.conf

    max_log_file = ```
  "
  desc  'fix', "
    Set the following parameter in `/etc/audit/auditd.conf`  in accordance with site policy:

    ```
    max_log_file = ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_rid:               '6.3.2.1'
  tag cis_number:            '6.3.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -E '^\s*max_log_file\s*=' /etc/audit/auditd.conf}) do
    its('stdout') { should match(/\S/) }
  end
end