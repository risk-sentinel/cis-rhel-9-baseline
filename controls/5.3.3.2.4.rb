# encoding: UTF-8

control 'C-5.3.3.2.4' do
  title 'Ensure password same consecutive characters is configured'
  desc  "
    The `pwquality` `maxrepeat` option sets the maximum number of allowed same consecutive characters in a new password.

    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'rationale', "
    The `pwquality` `maxrepeat` option sets the maximum number of allowed same consecutive characters in a new password.

    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
  "
  desc  'check', "
    Run the following command to verify that the `maxrepeat` option is set to `3` or less, not `0`, and follows local site policy:

    ```
    # grep -Psi -- '^\\h*maxrepeat\\h*=\\h*[1-3]\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    ```

    _Example output:_

    ```
    /etc/security/pwquality.conf.d/50-pwrepeat.conf:maxrepeat = 3
    ```

    Verify returned value(s) are `3` or less, not `0`, and meet local site policy

    Run the following command to verify that `maxrepeat` is not set, is `3` or less, not `0`, and conforms to local site policy:

    ```
    grep -Psi -- '^\\h*password\\h+(requisite|required|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n\\r]+\\h+)?maxrepeat\\h*=\\h*(0|[4-9]|[1-9][0-9]+)\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

    Nothing should be returned
    ```

    Notes: 
    - settings should be configured in only one location for clarity
    - Settings observe an order of precedence:
      - module arguments override the settings in the `/etc/security/pwquality.conf` configuration file
      - settings in the `/etc/security/pwquality.conf` configuration file override settings in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory
      - settings in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory are read in canonical order, with last read file containing the setting taking precedence
    - It is recommended that settings be configured in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory for clarity, convenience, and durability.
  "
  desc  'fix', "
    Create or modify a file ending in `.conf` in the `/etc/security/pwquality.conf.d/` directory or the file `/etc/security/pwquality.conf` and add or modify the following line to set `maxrepeat` to `3` or less and not `0`. Ensure setting conforms to local site policy:

    _Example:_

    ```
    # sed -ri 's/^\\s*maxrepeat\\s*=/# &/' /etc/security/pwquality.conf
    # printf '\\n%s' \"maxrepeat = 3\" >> /etc/security/pwquality.conf.d/50-pwrepeat.conf
    ```

    Run the following script to remove setting `maxrepeat` on the `pam_pwquality.so` module  in the PAM files:

    ```
    #!/usr/bin/env bash

    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+maxrepeat\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
       done
       authselect apply-changes
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.2.4'
  tag cis_number:            '5.3.3.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- '^\h*maxrepeat\h*=' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end