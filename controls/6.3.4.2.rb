# encoding: UTF-8

control 'C-6.3.4.2' do
  title 'Ensure audit log files mode is configured'
  desc  "
    Audit log files contain information about the system and system activity.

    Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.
  "
  desc  'rationale', "
    Audit log files contain information about the system and system activity.

    Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.
  "
  desc  'check', "
    Run the following script to verify audit log files are mode `0640` or more restrictive:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       l_perm_mask=\"0177\"
       if [ -e \"/etc/audit/auditd.conf\" ]; then
          l_audit_log_directory=\"$(dirname \"$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)\")\"
          if [ -d \"$l_audit_log_directory\" ]; then
             l_maxperm=\"$(printf '%o' $(( 0777 & ~$l_perm_mask )) )\"
             while IFS= read -r -d $'\\0' l_file; do
                while IFS=: read -r l_file_mode l_hr_file_mode; do
                   l_output2=\"$l_output2\\n  - File: \\\"$l_file\\\" is mode: \\\"$l_file_mode\\\"\\n     (should be mode: \\\"$l_maxperm\\\" or more restrictive)\\n\"
                done <<< \"$(stat -Lc '%#a:%A' \"$l_file\")\"
             done < <(find \"$l_audit_log_directory\" -maxdepth 1 -type f -perm /\"$l_perm_mask\" -print0)
          else
             l_output2=\"$l_output2\\n  - Log file directory not set in \\\"/etc/audit/auditd.conf\\\" please set log file directory\"
          fi
       else
          l_output2=\"$l_output2\\n  - File: \\\"/etc/audit/auditd.conf\\\" not found.\\n  -  Verify auditd is installed \"
       fi
       if [ -z \"$l_output2\" ]; then
          l_output=\"$l_output\\n  - All files in \\\"$l_audit_log_directory\\\" are mode: \\\"$l_maxperm\\\" or more restrictive\"
          echo -e \"\\n- Audit Result:\\n   PASS \\n - * Correctly configured * :$l_output\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :$l_output2\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following command to remove more permissive mode than `0640` from audit log files:

    ```
    # [ -f /etc/audit/auditd.conf ] && find \"$(dirname $(awk -F \"=\" '/^\\s*log_file/ {print $2}' /etc/audit/auditd.conf | xargs))\" -type f -perm /0137 -exec chmod u-x,g-wx,o-rwx {} +
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.3.4.2'
  tag cis_number:            '6.3.4.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030402r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{find /var/log/audit -type f -perm /0137 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end