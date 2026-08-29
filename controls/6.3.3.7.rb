# encoding: UTF-8

control 'C-6.3.3.7' do
  title 'Ensure unsuccessful file access attempts are collected'
  desc  "
    Monitor for unsuccessful attempts to access files. The following parameters are associated with system calls that control files:
    - creation - `creat`
    - opening - `open` , `openat`
    - truncation - `truncate` , `ftruncate`

    An audit log record will only be written if all of the following criteria is met for the user when trying to access a file:
    - a non-privileged user (auid>=UID_MIN)
    - is not a Daemon event (auid=4294967295/unset/-1)
    - if the system call returned EACCES (permission denied) or EPERM (some other permanent error associated with the specific system call)

    Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system.
  "
  desc  'rationale', "
    Monitor for unsuccessful attempts to access files. The following parameters are associated with system calls that control files:
    - creation - `creat`
    - opening - `open` , `openat`
    - truncation - `truncate` , `ftruncate`

    An audit log record will only be written if all of the following criteria is met for the user when trying to access a file:
    - a non-privileged user (auid>=UID_MIN)
    - is not a Daemon event (auid=4294967295/unset/-1)
    - if the system call returned EACCES (permission denied) or EPERM (some other permanent error associated with the specific system call)

    Failed attempts to open, create or truncate files could be an indication that an individual or process is trying to gain unauthorized access to the system.
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
     &&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) \\
     &&/ -S/ \\
     &&/creat/ \\
     &&/open/ \\
     &&/truncate/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output includes:

    ```
    -a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
    -a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=unset -k access
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
     &&(/ -F *exit=-EACCES/||/ -F *exit=-EPERM/) \\
     &&/ -S/ \\
     &&/creat/ \\
     &&/open/ \\
     &&/truncate/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output includes:

    ```
    -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access
    -a always,exit -F arch=b64 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access
    -a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat -F exit=-EACCES -F auid>=1000 -F auid!=-1 -F key=access
    -a always,exit -F arch=b32 -S open,truncate,ftruncate,creat,openat -F exit=-EPERM -F auid>=1000 -F auid!=-1 -F key=access
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor unsuccessful file access attempts.

    _Example:_

    ```
    # {
    UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n \"${UID_MIN}\" ] && printf \"
    -a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
    -a always,exit -F arch=b64 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=${UID_MIN} -F auid!=unset -k access
    -a always,exit -F arch=b32 -S creat,open,openat,truncate,ftruncate -F exit=-EPERM -F auid>=${UID_MIN} -F auid!=unset -k access
    \" >> /etc/audit/rules.d/50-access.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
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
  tag nist:                  ['AU-3 a', 'SC-12 (3)']
  tag cci:                   ['CCI-000130', 'CCI-002447']
  tag cis_rid:               '6.3.3.7'
  tag cis_number:            '6.3.3.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030307r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +access|key=access)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end