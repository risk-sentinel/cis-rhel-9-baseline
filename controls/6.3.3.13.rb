# encoding: UTF-8

control 'C-6.3.3.13' do
  title 'Ensure file deletion events by users are collected'
  desc  "
    Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for:
    - `unlink` - remove a file
    - `unlinkat` - remove a file attribute
    - `rename` - rename a file
    - `renameat` rename a file attribute
    system calls and tags them with the identifier \"delete\".

    Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system administrators will want to look for specific privileged files that are being deleted or altered.
  "
  desc  'rationale', "
    Monitor the use of system calls associated with the deletion or renaming of files and file attributes. This configuration statement sets up monitoring for:
    - `unlink` - remove a file
    - `unlinkat` - remove a file attribute
    - `rename` - rename a file
    - `renameat` rename a file attribute
    system calls and tags them with the identifier \"delete\".

    Monitoring these calls from non-privileged users could provide a system administrator with evidence that inappropriate removal of files and file attributes associated with protected files is occurring. While this audit option will look at all events, system administrators will want to look for specific privileged files that are being deleted or altered.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&/ -S/ \\
     &&(/unlink/||/rename/||/unlinkat/||/renameat/) \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
    -a always,exit -F arch=b32 -S unlink,unlinkat,rename,renameat -F auid>=1000 -F auid!=unset -k delete
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&/ -S/ \\
     &&(/unlink/||/rename/||/unlinkat/||/renameat/) \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
    -a always,exit -F arch=b32 -S unlink,rename,unlinkat,renameat -F auid>=1000 -F auid!=-1 -F key=delete
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor file deletion events by users.

    _Example:_

    ```
    # {
    UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n \"${UID_MIN}\" ] && printf \"
    -a always,exit -F arch=b64 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
    -a always,exit -F arch=b32 -S rename,unlink,unlinkat,renameat -F auid>=${UID_MIN} -F auid!=unset -F key=delete
    \" >> /etc/audit/rules.d/50-delete.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Load audit rules

    Merge and load the rules into active configuration:

    ```
    # augenrules --load
    ```

    Check if reboot is required.

    ```
    # if [[ $(auditctl -s | grep \"enabled\") =~ \"2\" ]]; then printf \"Reboot required to load rules\\n\"; fi
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'AU-3 a']
  tag cci:                   ['CCI-000011', 'CCI-000130']
  tag cis_rid:               '6.3.3.13'
  tag cis_number:            '6.3.3.13'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030313r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +delete|key=delete)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end