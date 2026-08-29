# encoding: UTF-8

control 'C-6.3.4.1' do
  title 'Ensure the audit log file directory mode is configured'
  desc  "
    The audit log directory contains audit log files.

    Audit information includes all information including: audit records, audit settings and audit reports. This information is needed to successfully audit system activity. This information must be protected from unauthorized modification or deletion. If this information were to be compromised, forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.
  "
  desc  'rationale', "
    The audit log directory contains audit log files.

    Audit information includes all information including: audit records, audit settings and audit reports. This information is needed to successfully audit system activity. This information must be protected from unauthorized modification or deletion. If this information were to be compromised, forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.
  "
  desc  'check', "
    Run the following script to verify the audit log directory is mode 0750 or more restrictive:

    ```
    #!/usr/bin/env bash

    {
       l_perm_mask=\"0027\"
       if [ -e \"/etc/audit/auditd.conf\" ]; then
          l_audit_log_directory=\"$(dirname \"$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)\")\"
          if [ -d \"$l_audit_log_directory\" ]; then
             l_maxperm=\"$(printf '%o' $(( 0777 & ~$l_perm_mask )) )\"
             l_directory_mode=\"$(stat -Lc '%#a' \"$l_audit_log_directory\")\"
             if [ $(( $l_directory_mode & $l_perm_mask )) -gt 0 ]; then
                echo -e \"\\n- Audit Result:\\n   FAIL \\n  - Directory: \\\"$l_audit_log_directory\\\" is mode: \\\"$l_directory_mode\\\"\\n     (should be mode: \\\"$l_maxperm\\\" or more restrictive)\\n\"
             else
                echo -e \"\\n- Audit Result:\\n   PASS \\n  - Directory: \\\"$l_audit_log_directory\\\" is mode: \\\"$l_directory_mode\\\"\\n     (should be mode: \\\"$l_maxperm\\\" or more restrictive)\\n\"
             fi        
          else
             echo -e \"\\n- Audit Result:\\n   FAIL \\n  - Log file directory not set in \\\"/etc/audit/auditd.conf\\\" please set log file directory\"
          fi
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n  - File: \\\"/etc/audit/auditd.conf\\\" not found\\n  -  Verify auditd is installed \"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following command to configure the audit log directory to have a mode of \"0750\" or less permissive: 

    ```
    # chmod g-w,o-rwx \"$(dirname \"$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)\")\"
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.3.4.1'
  tag cis_number:            '6.3.4.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030401r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe directory('/var/log/audit') do
    it { should exist }
    it { should_not be_more_permissive_than('0750') }
  end
end