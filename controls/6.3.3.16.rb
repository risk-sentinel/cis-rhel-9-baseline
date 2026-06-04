# encoding: UTF-8

control 'C-6.3.3.16' do
  title 'Ensure successful and unsuccessful attempts to use the setfacl command are collected'
  desc  "
    The operating system must generate audit records for successful/unsuccessful uses of the `setfacl` command

    This  utility  sets  Access  Control Lists (ACLs) of files and directories. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

    Audit records can be generated from various components within the information system (e.g., module or policy filter).
  "
  desc  'rationale', "
    The operating system must generate audit records for successful/unsuccessful uses of the `setfacl` command

    This  utility  sets  Access  Control Lists (ACLs) of files and directories. Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

    Audit records can be generated from various components within the information system (e.g., module or policy filter).
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&/ -F *perm=x/ \\
     &&/ -F *path=\\/usr\\/bin\\/setfacl/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=unset -k perm_chng
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&/ -F *perm=x/ \\
     &&/ -F *path=\\/usr\\/bin\\/setfacl/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -S all -F path=/usr/bin/setfacl -F perm=x -F auid>=1000 -F auid!=-1 -F key=perm_chng
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor successful and unsuccessful attempts to use the `setfacl` command.

    _Example:_

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && printf \"
    -a always,exit -F path=/usr/bin/setfacl -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k perm_chng
    \" >> /etc/audit/rules.d/50-perm_chng.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
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
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_rid:               '6.3.3.16'
  tag cis_number:            '6.3.3.16'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030316r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure successful and unsuccessful attempts to use the setfacl command are collected' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-06030316r1_rule.'
  end
end
