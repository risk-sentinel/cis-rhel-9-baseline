# encoding: UTF-8

control 'C-6.3.4.5' do
  title 'Ensure audit configuration files mode is configured'
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
    Run the following script to verify that the audit configuration files are mode `0640` or more restrictive:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\" l_perm_mask=\"0137\"
       l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_perm_mask )) )\"
       while IFS= read -r -d $'\\0' l_fname; do
          l_mode=$(stat -Lc '%#a' \"$l_fname\")
          if [ $(( \"$l_mode\" & \"$l_perm_mask\" )) -gt 0 ]; then
             l_output2=\"$l_output2\\n - file: \\\"$l_fname\\\" is mode: \\\"$l_mode\\\" (should be mode: \\\"$l_maxperm\\\" or more restrictive)\"
          fi
       done < <(find /etc/audit/ -type f \\( -name \"*.conf\" -o -name '*.rules' \\) -print0)
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n   PASS \\n - All audit configuration files are mode: \\\"$l_maxperm\\\" or more restrictive\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n$l_output2\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following command to remove more permissive mode than 0640 from the audit configuration files:

    ```
    # find /etc/audit/ -type f \\( -name '*.conf' -o -name '*.rules' \\) -exec chmod u-x,g-wx,o-rwx {} +
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.3.4.5'
  tag cis_number:            '6.3.4.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030405r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{find /etc/audit -type f -perm /0137 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end