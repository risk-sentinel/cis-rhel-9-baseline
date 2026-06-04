# encoding: UTF-8

control 'C-6.3.2.2' do
  title 'Ensure audit logs are not automatically deleted'
  desc  "
    The `max_log_file_action`  setting determines how to handle the audit log file reaching the max file size. A value of `keep_logs`  will rotate the logs but never delete old logs.

    In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history.
  "
  desc  'rationale', "
    The `max_log_file_action`  setting determines how to handle the audit log file reaching the max file size. A value of `keep_logs`  will rotate the logs but never delete old logs.

    In high security contexts, the benefits of maintaining a long audit history exceed the cost of storing the audit history.
  "
  desc  'check', "
    Run the following command and verify output matches:

    ```
    # grep max_log_file_action /etc/audit/auditd.conf

    max_log_file_action = keep_logs
    ```
  "
  desc  'fix', "
    Set the following parameter in `/etc/audit/auditd.conf:` 

    ```
    max_log_file_action = keep_logs
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_rid:               '6.3.2.2'
  tag cis_number:            '6.3.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -E '^\s*max_log_file_action\s*=\s*keep_logs' /etc/audit/auditd.conf}) do
    its('stdout') { should match(/\S/) }
  end
end