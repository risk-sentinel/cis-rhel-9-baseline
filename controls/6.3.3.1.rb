# encoding: UTF-8

control 'C-6.3.3.1' do
  title 'Ensure changes to system administration scope (sudoers) is collected'
  desc  "
    Monitor scope changes for system administrators. If the system has been properly configured to force system administrators to log in as themselves first and then use the `sudo` command to execute privileged commands, it is possible to monitor changes in scope. The file `/etc/sudoers`, or files in `/etc/sudoers.d`, will be written to when the file(s) or related attributes have changed. The audit records will be tagged with the identifier \"scope\".

    Changes in the `/etc/sudoers` and `/etc/sudoers.d` files can indicate that an unauthorized change has been made to the scope of system administrator activity.
  "
  desc  'rationale', "
    Monitor scope changes for system administrators. If the system has been properly configured to force system administrators to log in as themselves first and then use the `sudo` command to execute privileged commands, it is possible to monitor changes in scope. The file `/etc/sudoers`, or files in `/etc/sudoers.d`, will be written to when the file(s) or related attributes have changed. The audit records will be tagged with the identifier \"scope\".

    Changes in the `/etc/sudoers` and `/etc/sudoers.d` files can indicate that an unauthorized change has been made to the scope of system administrator activity.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # awk '/^ *-w/ \\
    &&/\\/etc\\/sudoers/ \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -w /etc/sudoers -p wa -k scope
    -w /etc/sudoers.d -p wa -k scope
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # auditctl -l | awk '/^ *-w/ \\
    &&/\\/etc\\/sudoers/ \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    ```

    Verify the output matches:

    ```
    -w /etc/sudoers -p wa -k scope
    -w /etc/sudoers.d -p wa -k scope
    ```
  "
  desc  'fix', "
    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor scope changes for system administrators.

    _Example:_

    ```
    # printf '%s\\n' \"-w /etc/sudoers -p wa -k scope\" \"-w /etc/sudoers.d -p wa -k scope\" >> /etc/audit/rules.d/50-scope.rules
    ```

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
  tag nist:                  ['CM-7 a', 'AU-3 a']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT', 'KSI-MLA-OSM']
  tag nist_r4:               ['AU-3', 'CM-7 a']
  tag cci:                   ['CCI-000381', 'CCI-000130']
  tag cis_rid:               '6.3.3.1'
  tag cis_number:            '6.3.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '/etc/sudoers' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end