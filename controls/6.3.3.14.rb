# encoding: UTF-8

control 'C-6.3.3.14' do
  title 'Ensure events that modify the system\'s Mandatory Access Controls are collected'
  desc  "
    Monitor SELinux, an implementation of mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the `/etc/selinux/` and `/usr/share/selinux/` directories.

    Note: If a different Mandatory Access Control method is used, changes to the corresponding directories should be audited.

    Changes to files in the `/etc/selinux/` and `/usr/share/selinux/` directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system.
  "
  desc  'rationale', "
    Monitor SELinux, an implementation of mandatory access controls. The parameters below monitor any write access (potential additional, deletion or modification of files in the directory) or attribute changes to the `/etc/selinux/` and `/usr/share/selinux/` directories.

    Note: If a different Mandatory Access Control method is used, changes to the corresponding directories should be audited.

    Changes to files in the `/etc/selinux/` and `/usr/share/selinux/` directories could indicate that an unauthorized user is attempting to modify access controls and change security contexts, leading to a compromise of the system.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # awk '/^ *-w/ \\
    &&(/\\/etc\\/selinux/ \\
      ||/\\/usr\\/share\\/selinux/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -w /etc/selinux -p wa -k MAC-policy
    -w /usr/share/selinux -p wa -k MAC-policy
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # auditctl -l | awk '/^ *-w/ \\
    &&(/\\/etc\\/selinux/ \\
      ||/\\/usr\\/share\\/selinux/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    ```

    Verify the output matches:

    ```
    -w /etc/selinux -p wa -k MAC-policy
    -w /usr/share/selinux -p wa -k MAC-policy
    ```
  "
  desc  'fix', "
    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor events that modify the system's Mandatory Access Controls.

    _Example:_

    ```
    # printf \"
    -w /etc/selinux -p wa -k MAC-policy
    -w /usr/share/selinux -p wa -k MAC-policy
    \" >> /etc/audit/rules.d/50-MAC-policy.rules
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
  tag nist:                  ['AC-2 a', 'AU-3 a']
  tag cci:                   ['CCI-002110', 'CCI-000130']
  tag cis_rid:               '6.3.3.14'
  tag cis_number:            '6.3.3.14'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030314r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +MAC-policy|key=MAC-policy)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end