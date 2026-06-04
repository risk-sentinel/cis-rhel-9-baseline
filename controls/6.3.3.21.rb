# encoding: UTF-8

control 'C-6.3.3.21' do
  title 'Ensure the running and on disk configuration is the same'
  desc  "
    The Audit system have both on disk and running configuration. It is possible for these configuration settings to differ.

    Note: Due to the limitations of `augenrules` and `auditctl`, it is not absolutely guaranteed that loading the rule sets via `augenrules --load` will result in all rules being loaded or even that the user will be informed if there was a problem loading the rules.

    Configuration differences between what is currently running and what is on disk could cause unexpected problems or may give a false impression of compliance requirements.
  "
  desc  'rationale', "
    The Audit system have both on disk and running configuration. It is possible for these configuration settings to differ.

    Note: Due to the limitations of `augenrules` and `auditctl`, it is not absolutely guaranteed that loading the rule sets via `augenrules --load` will result in all rules being loaded or even that the user will be informed if there was a problem loading the rules.

    Configuration differences between what is currently running and what is on disk could cause unexpected problems or may give a false impression of compliance requirements.
  "
  desc  'check', "
    Merged rule sets

    Ensure that all rules in `/etc/audit/rules.d` have been merged into `/etc/audit/audit.rules`:

    ```
    # augenrules --check

    /usr/sbin/augenrules: No change
    ```

    Should there be any drift, run `augenrules --load` to merge and load all rules.
  "
  desc  'fix', "
    If the rules are not aligned across all three () areas, run the following command to merge and load all rules:

    ```
    # augenrules --load
    ```

    Check if reboot is required.

    ```
    if [[ $(auditctl -s | grep \"enabled\") =~ \"2\" ]]; then echo \"Reboot required to load rules\"; fi
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_rid:               '6.3.3.21'
  tag cis_number:            '6.3.3.21'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030321r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{augenrules --check 2>/dev/null}) do
    its('stdout') { should match(/No change|No rules/) }
  end
end