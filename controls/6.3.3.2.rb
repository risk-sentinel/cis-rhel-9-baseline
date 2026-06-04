# encoding: UTF-8

control 'C-6.3.3.2' do
  title 'Ensure actions as another user are always logged'
  desc  "
    `sudo` provides users with temporary elevated privileges to perform operations, either as the superuser or another user.

    Creating an audit log of users with temporary elevated privileges and the operation(s) they performed is essential to reporting.  Administrators will want to correlate the events written to the audit trail with the records written to `sudo`'s logfile to verify if unauthorized commands have been executed.
  "
  desc  'rationale', "
    `sudo` provides users with temporary elevated privileges to perform operations, either as the superuser or another user.

    Creating an audit log of users with temporary elevated privileges and the operation(s) they performed is essential to reporting.  Administrators will want to correlate the events written to the audit trail with the records written to `sudo`'s logfile to verify if unauthorized commands have been executed.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # awk '/^ *-a *always,exit/ \\
    &&/ -F *arch=b(32|64)/ \\
    &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
    &&(/ -C *euid!=uid/||/ -C *uid!=euid/) \\
    &&/ -S *execve/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation 
    -a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # auditctl -l | awk '/^ *-a *always,exit/ \\
    &&/ -F *arch=b(32|64)/ \\
    &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
    &&(/ -C *euid!=uid/||/ -C *uid!=euid/) \\
    &&/ -S *execve/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation
    -a always,exit -F arch=b32 -S execve -C uid!=euid -F auid!=-1 -F key=user_emulation
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor elevated privileges.

    _Example:_

    ```
    # printf \"
    -a always,exit -F arch=b64 -C euid!=uid -F auid!=unset -S execve -k user_emulation 
    -a always,exit -F arch=b32 -C euid!=uid -F auid!=unset -S execve -k user_emulation
    \" >> /etc/audit/rules.d/50-user_emulation.rules
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
  tag nist:                  ['CM-6 b', 'AU-3 a']
  tag cci:                   ['CCI-000366', 'CCI-000130']
  tag cis_rid:               '6.3.3.2'
  tag cis_number:            '6.3.3.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030302r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +user_emulation|key=user_emulation)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end