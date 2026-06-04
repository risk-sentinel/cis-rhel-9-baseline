# encoding: UTF-8

control 'C-5.3.3.3.2' do
  title 'Ensure password history is enforced for the root user'
  desc  "
    If the `pwhistory` `enforce_for_root` option is enabled, the module will enforce password history for the root user as well

    Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password

    Note: These change only apply to accounts configured on the local system.
  "
  desc  'rationale', "
    If the `pwhistory` `enforce_for_root` option is enabled, the module will enforce password history for the root user as well

    Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password

    Note: These change only apply to accounts configured on the local system.
  "
  desc  'check', "
    Run the following command to verify that the `enforce_for_root` option is enabled in `/etc/pwhistory.conf`:

    ```
    # grep -Pi -- '^\\h*enforce_for_root\\b' /etc/security/pwhistory.conf

    enforce_for_root
    ```

    Notes: 
    - Settings observe an order of precedence. 
    - Module arguments override the settings in the `/etc/security/pwhistory.conf` configuration file
    - It is recommended that settings be configured in `/etc/security/pwhistory.conf` for clarity, convenience, and durability.
  "
  desc  'fix', "
    Edit or add the following line in `/etc/security/pwhistory.conf`:

    ```
    enforce_for_root
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.3.2'
  tag cis_number:            '5.3.3.3.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030302r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure password history is enforced for the root user' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0503030302r1_rule.'
  end
end
