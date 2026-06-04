# encoding: UTF-8

control 'C-6.3.4.7' do
  title 'Ensure audit configuration files group owner is configured'
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
    Run the following command to verify that the audit configuration files are owned by the group `root`: 

    ```
    # find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Run the following command to change group to `root`:

    ```
    # find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) ! -group root -exec chgrp root {} +
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.3.4.7'
  tag cis_number:            '6.3.4.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030407r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure audit configuration files group owner is configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-06030407r1_rule.'
  end
end
