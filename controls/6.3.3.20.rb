# encoding: UTF-8

control 'C-6.3.3.20' do
  title 'Ensure the audit configuration is immutable'
  desc  "
    Set system audit so that audit rules cannot be modified with `auditctl` . Setting the flag \"-e 2\" forces audit to be put in immutable mode. Audit changes can only be made on system reboot.

    Note: This setting will require the system to be rebooted to update the active `auditd` configuration settings.

    In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes.
  "
  desc  'rationale', "
    Set system audit so that audit rules cannot be modified with `auditctl` . Setting the flag \"-e 2\" forces audit to be put in immutable mode. Audit changes can only be made on system reboot.

    Note: This setting will require the system to be rebooted to update the active `auditd` configuration settings.

    In immutable mode, unauthorized users cannot execute changes to the audit system to potentially hide malicious activity and then put the audit rules back. Users would most likely notice a system reboot and that could alert administrators of an attempt to make unauthorized audit changes.
  "
  desc  'check', "
    Run the following command and verify output matches:

    ```
    # grep -Ph -- '^\\h*-e\\h+2\\b' /etc/audit/rules.d/*.rules | tail -1

    -e 2
    ```
  "
  desc  'fix', "
    Edit or create the file `/etc/audit/rules.d/99-finalize.rules` and add the line `-e 2` at the end of the file:

    _Example:_ 

    ```
    # printf '\\n%s' \"-e 2\" >> /etc/audit/rules.d/99-finalize.rules
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
  tag nist:                  ['AC-3', 'AC-2 f', 'IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000213', 'CCI-000011', 'CCI-000766', 'CCI-000130']
  tag cis_rid:               '6.3.3.20'
  tag cis_number:            '6.3.3.20'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030320r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '^\s*-e +2' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end