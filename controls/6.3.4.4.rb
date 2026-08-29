# encoding: UTF-8

control 'C-6.3.4.4' do
  title 'Ensure audit log files group owner is configured'
  desc  "
    Audit log files contain information about the system and system activity.

    Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.
  "
  desc  'rationale', "
    Audit log files contain information about the system and system activity.

    Access to audit records can reveal system and configuration data to attackers, potentially compromising its confidentiality.
  "
  desc  'check', "
    Run the following script to verify:
    - `log_group` parameter is set to either `adm` or `root` in `/etc/audit/auditd.conf`
    - audit log files are group owned by the group \"root\" or \"adm\" 

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       if [ -e \"/etc/audit/auditd.conf\" ]; then
          l_audit_log_directory=\"$(dirname \"$(awk -F= '/^\\s*log_file\\s*/{print $2}' /etc/audit/auditd.conf | xargs)\")\"
          l_audit_log_group=\"$(awk -F= '/^\\s*log_group\\s*/{print $2}' /etc/audit/auditd.conf | xargs)\"
          if grep -Pq -- '^\\h*(root|adm)\\h*$' <<< \"$l_audit_log_group\"; then
             l_output=\"$l_output\\n  - Log file group correctly set to: \\\"$l_audit_log_group\\\" in \\\"/etc/audit/auditd.conf\\\"\"
          else
             l_output2=\"$l_output2\\n  - Log file group is set to: \\\"$l_audit_log_group\\\" in \\\"/etc/audit/auditd.conf\\\"\\n     (should be set to group: \\\"root or adm\\\")\\n\"
          fi
          if [ -d \"$l_audit_log_directory\" ]; then
             while IFS= read -r -d $'\\0' l_file; do
                l_output2=\"$l_output2\\n  - File: \\\"$l_file\\\" is group owned by group: \\\"$(stat -Lc '%G' \"$l_file\")\\\"\\n     (should be group owned by group: \\\"root or adm\\\")\\n\"
             done < <(find \"$l_audit_log_directory\" -maxdepth 1 -type f \\( ! -group root -a ! -group adm \\) -print0)
          else
             l_output2=\"$l_output2\\n  - Log file directory not set in \\\"/etc/audit/auditd.conf\\\" please set log file directory\"
          fi
       else
          l_output2=\"$l_output2\\n  - File: \\\"/etc/audit/auditd.conf\\\" not found.\\n  -  Verify auditd is installed \"
       fi
       if [ -z \"$l_output2\" ]; then
          l_output=\"$l_output\\n  - All files in \\\"$l_audit_log_directory\\\" are group owned by group: \\\"root or adm\\\"\\n\"
          echo -e \"\\n- Audit Result:\\n   PASS \\n - * Correctly configured * :$l_output\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \" - * Correctly configured * :\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following command to configure the audit log files to be owned by `adm` group: 

    ```
    # find $(dirname $(awk -F\"=\" '/^\\s*log_file\\s*=\\s*/ {print $2}' /etc/audit/auditd.conf | xargs)) -type f \\( ! -group adm -a ! -group root \\) -exec chgrp adm {} +
    ```

    Run the following command to configure the audit log files to be owned by the `adm` group:

    ```
    # chgrp adm /var/log/audit/
    ```

    Run the following command to set the `log_group` parameter in the audit configuration file to `log_group = adm`:

    ```
    # sed -ri 's/^\\s*#?\\s*log_group\\s*=\\s*\\S+(\\s*#.*)?.*$/log_group = adm\\1/' /etc/audit/auditd.conf
    ```

    Run the following command to restart the audit daemon to reload the configuration file: 

    ```
    # systemctl restart auditd
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.3.4.4'
  tag cis_number:            '6.3.4.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030404r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{find /var/log/audit -type f ! -group root 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end