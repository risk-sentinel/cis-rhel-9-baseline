# encoding: UTF-8

control 'C-5.3.3.2.6' do
  title 'Ensure password dictionary check is enabled'
  desc  "
    The `pwquality` `dictcheck` option sets whether to check for the words from the `cracklib` dictionary.

    If the operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.
  "
  desc  'rationale', "
    The `pwquality` `dictcheck` option sets whether to check for the words from the `cracklib` dictionary.

    If the operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses, and brute-force attacks.
  "
  desc  'check', "
    Run the following command to verify that the `dictcheck` option is not set to `0` (disabled) in a pwquality configuration file:

    ```
    # grep -Psi -- '^\\h*dictcheck\\h*=\\h*0\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf

    Nothing should be returned
    ```

    Run the following command to verify that the `dictcheck` option is not set to `0` (disabled) as a module argument in a PAM file:

    ```
    # grep -Psi -- '^\\h*password\\h+(requisite|required|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n\\r]+\\h+)?dictcheck\\h*=\\h*0\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

    Nothing should be returned
    ```

    Notes: 
    - Settings observe an order of precedence:
      - module arguments override the settings in the `/etc/security/pwquality.conf` configuration file
      - settings in the `/etc/security/pwquality.conf` configuration file override settings in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory
      - settings in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory are read in canonical order, with last read file containing the setting taking precedence
    - It is recommended that settings be configured in a `.conf` file in the `/etc/security/pwquality.conf.d/` directory for clarity, convenience, and durability.
  "
  desc  'fix', "
    Edit any file ending in `.conf` in the `/etc/security/pwquality.conf.d/` directory and/or the file `/etc/security/pwquality.conf` and comment out or remove any instance of `dictcheck = 0`: 

    _Example:_

    ```
    # sed -ri 's/^\\s*dictcheck\\s*=/# &/' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    ```

    Run the following script to remove setting `dictcheck` on the `pam_pwquality.so` module  in the PAM files:

    ```
    #!/usr/bin/env bash

    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+dictcheck\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
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
  tag cis_rid:               '5.3.3.2.6'
  tag cis_number:            '5.3.3.2.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030206r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- '^\h*dictcheck\h*=\h*0\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end