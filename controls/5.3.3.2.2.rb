# encoding: UTF-8

control 'C-5.3.3.2.2' do
  title 'Ensure password length is configured'
  desc  "
    `minlen` - Minimum acceptable size for the new password (plus one if credits are not disabled which is the            default). Cannot be set to lower value than 6.

    Strong passwords protect systems from being hacked through brute force methods.
  "
  desc  'rationale', "
    `minlen` - Minimum acceptable size for the new password (plus one if credits are not disabled which is the            default). Cannot be set to lower value than 6.

    Strong passwords protect systems from being hacked through brute force methods.
  "
  desc  'check', "
    Run the following command to verify that password length is `14` or more characters, and conforms to local site policy:

    ```
    # grep -Psi -- '^\\h*minlen\\h*=\\h*(1[4-9]|[2-9][0-9]|[1-9][0-9]{2,})\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    ```

    _Example output:_

    ```
    /etc/security/pwquality.conf.d/50-pwlength.conf:minlen = 14
    ```

    Verify returned value(s) are no less than `14` characters and meet local site policy

    Run the following command to verify that `minlen` is not set, or is `14` or more characters, and conforms to local site policy:

    ```
    grep -Psi -- '^\\h*password\\h+(requisite|required|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n\\r]+\\h+)?minlen\\h*=\\h*([0-9]|1[0-3])\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

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
    Create or modify a file ending in `.conf` in the `/etc/security/pwquality.conf.d/` directory or the file `/etc/security/pwquality.conf` and add or modify the following line to set password length of `14` or more characters. Ensure that password length conforms to local site policy: 

    _Example:_

    ```
    # sed -ri 's/^\\s*minlen\\s*=/# &/' /etc/security/pwquality.conf
    # printf '\\n%s' \"minlen = 14\" >> /etc/security/pwquality.conf.d/50-pwlength.conf
    ```

    Run the following script to remove setting `minlen` on the `pam_pwquality.so` module  in the PAM files:

    ```
    #!/usr/bin/env bash

    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+minlen\\s*=\\s*[0-9]+)(.*$)/\\1\\4/' \"$l_authselect_file\"
       done
       authselect apply-changes
    }
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag nist_r4:               ['IA-5 (1) (e)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.2.2'
  tag cis_number:            '5.3.3.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- '^\h*minlen\h*=' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end