# encoding: UTF-8

control 'C-5.3.3.4.4' do
  title 'Ensure pam_unix includes use_authtok'
  desc  "
    `use_authtok` - When password changing enforce the module to set the new password to the one provided by a previously stacked password module

    `use_authtok` allows multiple pam modules to confirm a new password before it is accepted.
  "
  desc  'rationale', "
    `use_authtok` - When password changing enforce the module to set the new password to the one provided by a previously stacked password module

    `use_authtok` allows multiple pam modules to confirm a new password before it is accepted.
  "
  desc  'check', "
    Run the following command to verify that `use_authtok` is set on the `pam_unix.so` module lines in the password stack:

    ```
    # grep -P -- '^\\h*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b' /etc/pam.d/{password,system}-auth
    ```

    Output should be similar to:

    ```
    /etc/pam.d/password-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok

    /etc/pam.d/system-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok
    ```

    Verify that the lines include `use_authtok`
  "
  desc  'fix', "
    Run the following script to verify the active authselect profile includes `use_authtok` on the password stack's `pam_unix.so` module lines:

    ```
    #!/usr/bin/env bash

    {
       l_pam_profile=\"$(head -1 /etc/authselect/authselect.conf)\"
       if grep -Pq -- '^custom\\/' <<< \"$l_pam_profile\"; then
          l_pam_profile_path=\"/etc/authselect/$l_pam_profile\"
       else
          l_pam_profile_path=\"/usr/share/authselect/default/$l_pam_profile\"
       fi
       grep -P -- '^\\h*password\\h+(requisite|required|sufficient)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b' \"$l_pam_profile_path\"/{password,system}-auth
    }
    ```

    _Example output:_

    ```
    /etc/authselect/custom/custom-profile/password-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok

    /etc/authselect/custom/custom-profile/system-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok
    ```

    - IF - the output does not include `use_authtok`, run the following script:

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
          if  grep -Pq '^\\h*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?use_authtok\\b' \"$l_authselect_file\"; then
             echo \"- \\\"use_authtok\\\" is already set\"
          else
             echo \"- \\\"use_authtok\\\" is not set. Updating template\"
             sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_unix\\.so\\s+.*)$/& use_authtok/g' \"$l_authselect_file\"
          fi
       done
    }
    ```

    Run the following command to update the `password-auth` and `system-auth` files in `/etc/pam.d` to include the `use_authtok` argument on the password stack's `pam_unix.so` lines:

    ```
    # authselect apply-changes
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-28', 'CM-8 a 1']
  tag cci:                   ['CCI-001199', 'CCI-000389']
  tag cis_rid:               '5.3.3.4.4'
  tag cis_number:            '5.3.3.4.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030404r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- 'pam_unix\.so[^\n]*\buse_authtok\b' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end