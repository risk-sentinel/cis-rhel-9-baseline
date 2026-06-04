# encoding: UTF-8

control 'C-5.3.3.1.3' do
  title 'Ensure password failed attempts lockout includes root account'
  desc  "
    `even_deny_root` - Root account can become locked as well as regular accounts

    `root_unlock_time=n` - This option implies even_deny_root option. Allow access after n seconds to root account after the account is locked. In case the option is not specified the value is the same as of the unlock_time option.

    Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'rationale', "
    `even_deny_root` - Root account can become locked as well as regular accounts

    `root_unlock_time=n` - This option implies even_deny_root option. Allow access after n seconds to root account after the account is locked. In case the option is not specified the value is the same as of the unlock_time option.

    Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'check', "
    Run the following command to verify that `even_deny_root` and/or `root_unlock_time` is enabled:

    ```
    # grep -Pi -- '^\\h*(even_deny_root|root_unlock_time\\h*=\\h*\\d+)\\b' /etc/security/faillock.conf
    ```

    _Example output:_

    ```
    even_deny_root

    --AND/OR--

    root_unlock_time = 60
    ```

    Run the following command to verify that - IF - `root_unlock_time` is set, it is set to `60` (One minute) or more:

    ```
    # grep -Pi -- '^\\h*root_unlock_time\\h*=\\h*([1-9]|[1-5][0-9])\\b' /etc/security/faillock.conf

    Nothing should be returned
    ```

    Run the following command to check the `pam_faillock.so` module for the `root_unlock_time` argument. Verify - IF - `root_unlock_time` is set, it is set to `60` (One minute) or more:

    ```
    # grep -Pi -- '^\\h*auth\\h+([^#\\n\\r]+\\h+)pam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?root_unlock_time\\h*=\\h*([1-9]|[1-5][0-9])\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Edit `/etc/security/faillock.conf`:
    - Remove or update any line containing `root_unlock_time`, - OR - set it to a value of `60` or more
    - Update or add the following line:

    ```
    even_deny_root
    ```

    Run the following script to remove the `even_deny_root` and `root_unlock_time` arguments from the `pam_faillock.so` module in the PAM files:

    ```
    #!/usr/bin/env bash
    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*auth\\s+(.*)\\s+pam_faillock\\.so.*)(\\s+even_deny_root)(.*$)/\\1\\4/' \"$l_authselect_file\"
         sed -ri 's/(^\\s*auth\\s+(.*)\\s+pam_faillock\\.so.*)(\\s+root_unlock_time\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
       done
       authselect apply-changes
    }
    ``
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'CM-6 a']
  tag cci:                   ['CCI-000011', 'CCI-000363']
  tag cis_rid:               '5.3.3.1.3'
  tag cis_number:            '5.3.3.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -P -- '^\h*(even_deny_root|root_unlock_time\h*=)' /etc/security/faillock.conf}) do
    its('stdout') { should match(/\S/) }
  end
end