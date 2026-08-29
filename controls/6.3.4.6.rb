# encoding: UTF-8

control 'C-6.3.4.6' do
  title 'Ensure audit configuration files owner is configured'
  desc  "
    Audit configuration files control auditd and what events are audited.

    Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events. 

    Misconfigured audit configuration files may prevent the auditing of critical events or impact the system's performance by overwhelming the audit log. Misconfiguration of the audit configuration files may also make it more difficult to establish and investigate events relating to an incident.
  "
  desc  'rationale', "
    Audit configuration files control auditd and what events are audited.

    Access to the audit configuration files could allow unauthorized personnel to prevent the auditing of critical events. 

    Misconfigured audit configuration files may prevent the auditing of critical events or impact the system's performance by overwhelming the audit log. Misconfiguration of the audit configuration files may also make it more difficult to establish and investigate events relating to an incident.
  "
  desc  'check', "
    Run the following command to verify that the audit configuration files have mode 640 or more restrictive and are owned by the root user and root group: 

    ```
    # find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Run the following command to change ownership to `root` user:

    ```
    # find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -user root -exec chown root {} +
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.3.4.6'
  tag cis_number:            '6.3.4.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030406r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{find /etc/audit -type f ! -user root 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end