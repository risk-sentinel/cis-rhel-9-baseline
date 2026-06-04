# encoding: UTF-8

control 'C-5.3.3.4.2' do
  title 'Ensure pam_unix does not include remember'
  desc  "
    The `remember=n` argument saves the last n passwords for each user in `/etc/security/opasswd` in order to force password change history and keep the user from alternating between the same password too frequently. The MD5 password hash algorithm is used for storing the old passwords. Instead of this option the `pam_pwhistory` module should be used. The `pam_pwhistory` module saves the last n passwords for each user in `/etc/security/opasswd` using the password hash algorithm set on the `pam_unix` module. This allows for the `sha512` hash algorithm to be used.

    The `remember=n` argument should be removed to ensure a strong password hashing algorithm is being used. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local user's old passwords stored in `/etc/security/opasswd`.
  "
  desc  'rationale', "
    The `remember=n` argument saves the last n passwords for each user in `/etc/security/opasswd` in order to force password change history and keep the user from alternating between the same password too frequently. The MD5 password hash algorithm is used for storing the old passwords. Instead of this option the `pam_pwhistory` module should be used. The `pam_pwhistory` module saves the last n passwords for each user in `/etc/security/opasswd` using the password hash algorithm set on the `pam_unix` module. This allows for the `sha512` hash algorithm to be used.

    The `remember=n` argument should be removed to ensure a strong password hashing algorithm is being used. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local user's old passwords stored in `/etc/security/opasswd`.
  "
  desc  'check', "
    Run the following command to verify that the `remember` argument is not set on the `pam_unix.so` module:

    ```
    # grep -Pi '^\\h*password\\h+([^#\\n\\r]+\\h+)?pam_unix\\.so\\b' /etc/pam.d/{password,system}-auth | grep -Pv '\\bremember=\\d\\b'
    ```

    Output should be similar to:

    ```
    /etc/pam.d/password-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok

    /etc/pam.d/system-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok
    ```
  "
  desc  'fix', "
    Run the following script to verify the active authselect profile doesn't include the `remember` argument on the `pam_unix.so` module lines:

    ```
    #!/usr/bin/env bash

    {
       l_pam_profile=\"$(head -1 /etc/authselect/authselect.conf)\"
       if grep -Pq -- '^custom\\/' <<< \"$l_pam_profile\"; then
          l_pam_profile_path=\"/etc/authselect/$l_pam_profile\"
       else
          l_pam_profile_path=\"/usr/share/authselect/default/$l_pam_profile\"
       fi
       grep -P -- '^\\h*password\\h+([^#\\n\\r]+\\h+)pam_unix\\.so\\b' \"$l_pam_profile_path\"/{password,system}-auth
    }
    ```

    Output should be similar to:

    ```
    /etc/authselect/custom/custom-profile/password-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok

    /etc/authselect/custom/custom-profile/system-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok
    ```

    - IF - any line includes `remember=`, run the following script to remove the `remember=` from the `pam_unix.so` lines in the active authselect profile `password-auth` and system-auth` templates:

    ```
    #!/usr/bin/env bash

    {
       l_pam_profile=\"$(head -1 /etc/authselect/authselect.conf)\"
       if grep -Pq -- '^custom\\/' <<< \"$l_pam_profile\"; then
          l_pam_profile_path=\"/etc/authselect/$l_pam_profile\"
       else
          l_pam_profile_path=\"/usr/share/authselect/default/$l_pam_profile\"
       fi
       for l_authselect_file in \"$l_pam_profile_path\"/password-auth \"$l_pam_profile_path\"/system-auth; do
          sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_unix\\.so\\s+.*)(remember=[1-9][0-9]*)(\\s*.*)$/\\1\\4/g' \"$l_authselect_file\"
       done
    }
    ```

    Run the following command to update the `password-auth` and system-auth` files in `/etc/pam.d` to include pam_unix.so without the remember` argument:

    ```
    # authselect apply-changes
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.4.2'
  tag cis_number:            '5.3.3.4.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030402r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure pam_unix does not include remember' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0503030402r1_rule.'
  end
end
