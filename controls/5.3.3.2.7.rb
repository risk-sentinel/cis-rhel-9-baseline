# encoding: UTF-8

control 'C-5.3.3.2.7' do
  title 'Ensure password quality is enforced for the root user'
  desc  "
    If the `pwquality` `enforce_for_root` option is enabled, the module will return error on failed check even if the user changing the password is root. 

    This option is off by default which means that just the message about the failed check is printed but root can change the password anyway. 

    Note: The root is not asked for an old password so the checks that compare the old and new password are not performed.

    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', "
    If the `pwquality` `enforce_for_root` option is enabled, the module will return error on failed check even if the user changing the password is root. 

    This option is off by default which means that just the message about the failed check is printed but root can change the password anyway. 

    Note: The root is not asked for an old password so the checks that compare the old and new password are not performed.

    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'check', "
    Run the following command to verify that the `enforce_for_root` option is enabled in a pwquality configuration file:

    ```
    # grep -Psi -- '^\\h*enforce_for_root\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    ```

    _Example output:_

    ```
    /etc/security/pwquality.conf.d/50-pwroot.conf:enforce_for_root
    ```

    Notes: 
    - Settings observe an order of precedence:
      - module arguments override the settings in the `/etc/security/pwquality.conf` configuration file
      - settings in the `/etc/security/pwquality.conf` configuration file override settings in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory
      - settings in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory are read in canonical order, with last read file containing the setting taking precedence
    - It is recommended that settings be configured in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory for clarity, convenience, and durability.
  "
  desc  'fix', "
    Edit or add the following line in a `*.conf` file in `/etc/security/pwquality.conf.d` or in   `/etc/security/pwquality.conf`:

    _Example:_

    ```
    printf '\\n%s\\n' \"enforce_for_root\" >> /etc/security/pwquality.conf.d/50-pwroot.conf
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.2.7'
  tag cis_number:            '5.3.3.2.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030207r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -rP -- '^\h*enforce_for_root\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end