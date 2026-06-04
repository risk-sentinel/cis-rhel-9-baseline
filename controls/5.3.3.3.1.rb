# encoding: UTF-8

control 'C-5.3.3.3.1' do
  title 'Ensure password history remember is configured'
  desc  "
    The `/etc/security/opasswd` file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords. The number of passwords remembered is set via the remember argument value in set for the `pam_pwhistory` module.

    - remember= - ` ` is the number of old passwords to remember

    Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password.

    Note: These change only apply to accounts configured on the local system.
  "
  desc  'rationale', "
    The `/etc/security/opasswd` file stores the users' old passwords and can be checked to ensure that users are not recycling recent passwords. The number of passwords remembered is set via the remember argument value in set for the `pam_pwhistory` module.

    - remember= - ` ` is the number of old passwords to remember

    Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password.

    Note: These change only apply to accounts configured on the local system.
  "
  desc  'check', "
    Run the following command and verify that the remember option is set to `24` or more and meets local site policy in `/etc/security/pwhistory.conf`:

    ```
    # grep -Pi -- '^\\h*remember\\h*=\\h*(2[4-9]|[3-9][0-9]|[1-9][0-9]{2,})\\b' /etc/security/pwhistory.conf

    remember = 24
    ```

    Run the following command to verify that the remember option is not set to less than `24` on the `pam_pwhistory.so` module in `/etc/pam.d/password-auth` and `/etc/pam.d/system-auth`:

    ```
    # grep -Pi -- '^\\h*password\\h+(requisite|required|sufficient)\\h+pam_pwhistory\\.so\\h+([^#\\n\\r]+\\h+)?remember=(2[0-3]|1[0-9]|[0-9])\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Edit or add the following line in `/etc/security/pwhistory.conf`:

    ```
    remember = 24
    ```

    Run the following script to remove the `remember` argument from the `pam_pwhistory.so` module in `/etc/pam.d/system-auth` and `/etc/pam.d/password-auth`:

    ```
    #!/usr/bin/env bash

    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_pwhistory\\.so.*)(\\s+remember\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
       done
       authselect apply-changes
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.3.1'
  tag cis_number:            '5.3.3.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure password history remember is configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0503030301r1_rule.'
  end
end
