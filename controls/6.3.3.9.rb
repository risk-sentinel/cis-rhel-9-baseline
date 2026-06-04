# encoding: UTF-8

control 'C-6.3.3.9' do
  title 'Ensure discretionary access control permission modification events are collected'
  desc  "
    Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The following commands and system calls effect the permissions, ownership and various attributes of files.
    - `chmod`
    - `fchmod`
    - `fchmodat`
    - `chown`
    - `fchown`
    - `fchownat`
    - `lchown`
    - `setxattr`
    - `lsetxattr`
    - `fsetxattr`
    - `removexattr`
    - `lremovexattr`
    - `fremovexattr`

    In all cases, an audit record will only be written for non-system user ids and will ignore Daemon events. All audit records will be tagged with the identifier \"perm_mod.\"

    Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation.
  "
  desc  'rationale', "
    Monitor changes to file permissions, attributes, ownership and group. The parameters in this section track changes for system calls that affect file permissions and attributes. The following commands and system calls effect the permissions, ownership and various attributes of files.
    - `chmod`
    - `fchmod`
    - `fchmodat`
    - `chown`
    - `fchown`
    - `fchownat`
    - `lchown`
    - `setxattr`
    - `lsetxattr`
    - `fsetxattr`
    - `removexattr`
    - `lremovexattr`
    - `fremovexattr`

    In all cases, an audit record will only be written for non-system user ids and will ignore Daemon events. All audit records will be tagged with the identifier \"perm_mod.\"

    Monitoring for changes in file attributes could alert a system administrator to activity that could indicate intruder activity or policy violation.
  "
  desc  'check', "
    Note: Output showing all audited syscalls, e.g. (-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat,chmod,fchmod,fchmodat,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod) is also acceptable. These have been separated by function on the displayed output for clarity.

    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -S/ \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&(/chmod/||/fchmod/||/fchmodat/ \\
       ||/chown/||/fchown/||/fchownat/||/lchown/ \\
       ||/setxattr/||/lsetxattr/||/fsetxattr/ \\
       ||/removexattr/||/lremovexattr/||/fremovexattr/) \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:
    ```
    -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=unset -F key=perm_mod
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -S/ \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&(/chmod/||/fchmod/||/fchmodat/ \\
       ||/chown/||/fchown/||/fchownat/||/lchown/ \\
       ||/setxattr/||/lsetxattr/||/fsetxattr/ \\
       ||/removexattr/||/lremovexattr/||/fremovexattr/) \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
    -a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor discretionary access control permission modification events.

    _Example:_

    ```
    # {
    UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n \"${UID_MIN}\" ] && printf \"
    -a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S lchown,fchown,chown,fchownat -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    -a always,exit -F arch=b32 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=${UID_MIN} -F auid!=unset -F key=perm_mod
    \" >> /etc/audit/rules.d/50-perm_mod.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
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
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 a', 'AU-3 a']
  tag cci:                   ['CCI-002110', 'CCI-000130']
  tag cis_rid:               '6.3.3.9'
  tag cis_number:            '6.3.3.9'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030309r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure discretionary access control permission modification events are collected' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-06030309r1_rule.'
  end
end
