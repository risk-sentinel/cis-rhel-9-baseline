# encoding: UTF-8

control 'C-6.3.4.8' do
  title 'Ensure audit tools mode is configured'
  desc  "
    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

    Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Protecting audit tools is necessary to prevent unauthorized operation on audit information.
  "
  desc  'rationale', "
    Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.

    Protecting audit information includes identifying and protecting the tools used to view and manipulate log data. Protecting audit tools is necessary to prevent unauthorized operation on audit information.
  "
  desc  'check', "
    Run the following script to verify the audit tools  are mode `0755` or more restrictive:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\" l_perm_mask=\"0022\"
       l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_perm_mask )) )\"
       a_audit_tools=(\"/sbin/auditctl\" \"/sbin/aureport\" \"/sbin/ausearch\" \"/sbin/autrace\" \"/sbin/auditd\" \"/sbin/augenrules\")
       for l_audit_tool in \"${a_audit_tools[@]}\"; do
          l_mode=\"$(stat -Lc '%#a' \"$l_audit_tool\")\"
          if [ $(( \"$l_mode\" & \"$l_perm_mask\" )) -gt 0 ]; then
             l_output2=\"$l_output2\\n - Audit tool \\\"$l_audit_tool\\\" is mode: \\\"$l_mode\\\" and should be mode: \\\"$l_maxperm\\\" or more restrictive\"
          else
             l_output=\"$l_output\\n - Audit tool \\\"$l_audit_tool\\\" is correctly configured to mode: \\\"$l_mode\\\"\"
          fi
       done
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n   PASS \\n - * Correctly configured * :$l_output\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n - * Correctly configured * :\\n$l_output\\n\"
       fi
       unset a_audit_tools
    }
    ```
  "
  desc  'fix', "
    Run the following command to remove more permissive mode from the audit tools: 

    ```
    # chmod go-w /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/augenrules
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.3.4.8'
  tag cis_number:            '6.3.4.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030408r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{find /sbin/auditctl /sbin/auditd /sbin/ausearch /sbin/aureport /sbin/autrace /sbin/augenrules /sbin/audisp-remote /sbin/audisp-syslog -perm /0022 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end