# encoding: UTF-8

control 'C-5.3.3.2.3' do
  title 'Ensure password complexity is configured'
  desc  "
    Password complexity can be set through:
    - `minclass` - The minimum number of classes of characters required in a new password. (digits, uppercase, lowercase, others). e.g. `minclass = 4` requires digits, uppercase, lower case, and special characters. 
    - `dcredit` - The maximum credit for having digits in the new password. If less than `0` it is the minimum number of digits in the new password. e.g. `dcredit = -1` requires at least one digit
    - `ucredit` - The maximum credit for having uppercase characters in the new password. If less than 0 it is the minimum number of uppercase characters in the new password. e.g. `ucredit = -1` requires at least one uppercase character
    - `ocredit` - The maximum credit for having other characters in the new password.  If less than 0 it is the minimum number of other characters in the new password. e.g. `ocredit = -1` requires at least one special character
    - `lcredit` - The maximum credit for having lowercase characters in the new password.  If less than 0 it is the minimum number of lowercase characters in the new password. e.g. `lcredit = -1` requires at least one lowercase character

    Strong passwords protect systems from being hacked through brute force methods.
  "
  desc  'rationale', "
    Password complexity can be set through:
    - `minclass` - The minimum number of classes of characters required in a new password. (digits, uppercase, lowercase, others). e.g. `minclass = 4` requires digits, uppercase, lower case, and special characters. 
    - `dcredit` - The maximum credit for having digits in the new password. If less than `0` it is the minimum number of digits in the new password. e.g. `dcredit = -1` requires at least one digit
    - `ucredit` - The maximum credit for having uppercase characters in the new password. If less than 0 it is the minimum number of uppercase characters in the new password. e.g. `ucredit = -1` requires at least one uppercase character
    - `ocredit` - The maximum credit for having other characters in the new password.  If less than 0 it is the minimum number of other characters in the new password. e.g. `ocredit = -1` requires at least one special character
    - `lcredit` - The maximum credit for having lowercase characters in the new password.  If less than 0 it is the minimum number of lowercase characters in the new password. e.g. `lcredit = -1` requires at least one lowercase character

    Strong passwords protect systems from being hacked through brute force methods.
  "
  desc  'check', "
    Run the following command to verify that complexity conforms to local site policy:

    ```
    # grep -Psi -- '^\\h*(minclass|[dulo]credit)\\b' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
    ```

    _Example output:_

    ```
    /etc/security/pwquality.conf.d/50-pwcomplexity.conf:minclass = 4
      -- AND/OR --
    /etc/security/pwquality.conf.d/50-pwcomplexity.conf:dcredit = -1
    /etc/security/pwquality.conf.d/50-pwcomplexity.conf:ucredit = -1
    /etc/security/pwquality.conf.d/50-pwcomplexity.conf:ocredit = -1
    /etc/security/pwquality.conf.d/50-pwcomplexity.conf:lcredit = -1
    ```

    Run the following command to verify that:
    - `minclass` is not set to less than `4`
    - `dcredit`, `ucredit`, `lcredit`, and `ocredit` are not set to `0` or greater

    ```
    grep -Psi -- '^\\h*password\\h+(requisite|required|sufficient)\\h+pam_pwquality\\.so\\h+([^#\\n\\r]+\\h+)?(minclass=[0-3]|[dulo]credit=[^-]\\d*)\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

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
    Create or modify a file ending in `.conf` in the `/etc/security/pwquality.conf.d/` directory or the file `/etc/security/pwquality.conf` and add or modify the following line to set:
    - `minclass = 4`

    --AND/OR--
    - `dcredit = -_N_`
    - `ucredit = -_N_`
    - `ocredit = -_N_`
    - `lcredit = -_N_`

    _Example:_

    ```
    # sed -ri 's/^\\s*minclass\\s*=/# &/' /etc/security/pwquality.conf
    # printf '\\n%s' \"minclass = 4\" >> /etc/security/pwquality.conf.d/50-pwcomplexity.conf
    ```

    --AND/OR--

    ```
    # sed -ri 's/^\\s*[dulo]credit\\s*=/# &/' /etc/security/pwquality.conf
    # printf '%s\\n' \"dcredit = -1\" \"ucredit = -1\" \"ocredit = -1\" \"lcredit = -1\" > /etc/security/pwquality.conf.d/50-pwcomplexity.conf
    ```

    Run the following script to remove setting `minclass`, `dcredit`, `ucredit`, `lcredit`, and `ocredit` on the `pam_pwquality.so` module in the PAM files

    ```
    #!/usr/bin/env bash

    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+minclass\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+dcredit\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+ucredit\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+lcredit\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwquality\\.so.*)(\\s+ocredit\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
       done
       authselect apply-changes
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.2.3'
  tag cis_number:            '5.3.3.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- '^\h*(minclass|[dulo]credit)\h*=' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end