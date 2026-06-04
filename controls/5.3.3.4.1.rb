# encoding: UTF-8

control 'C-5.3.3.4.1' do
  title 'Ensure pam_unix does not include nullok'
  desc  "
    The `nullok` argument overrides the default action of `pam_unix.so` to not permit the user access to a service if their official password is blank.

    Using a strong password is essential to helping protect personal and sensitive information from unauthorized access
  "
  desc  'rationale', "
    The `nullok` argument overrides the default action of `pam_unix.so` to not permit the user access to a service if their official password is blank.

    Using a strong password is essential to helping protect personal and sensitive information from unauthorized access
  "
  desc  'check', "
    Run the following command to verify that the `nullok` argument is not set on the `pam_unix.so` module:

    ```
    # grep -P -- '^\\h*(auth|account|password|session)\\h+(requisite|required|sufficient)\\h+pam_unix\\.so\\b' /etc/pam.d/{password,system}-auth
    ```

    Verify that none of the returned lines includes `nullok`. Output should be similar to:

    ```
    /etc/pam.d/password-auth:auth   sufficient   pam_unix.so
    /etc/pam.d/password-auth:account   required   pam_unix.so
    /etc/pam.d/password-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok
    /etc/pam.d/password-auth:session   required   pam_unix.so

    /etc/pam.d/system-auth:auth   sufficient   pam_unix.so
    /etc/pam.d/system-auth:account   required   pam_unix.so
    /etc/pam.d/system-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok
    /etc/pam.d/system-auth:session   required   pam_unix.so
    ```
  "
  desc  'fix', "
    Run the following script to verify that the active authselect profile's `system-auth` and `password-auth` files include `{if not \"without-nullok\":nullok}` - OR - don't include the `nullok` option on the `pam_unix.so` module:

    ```
    {
       l_module_name=\"unix\"
       l_profile_name=\"$(head -1 /etc/authselect/authselect.conf)\"
       if [[ ! \"$l_profile_name\" =~ ^custom\\/ ]]; then
          echo \" - Follow Recommendation \\\"Ensure custom authselect profile is used\\\" and then return to this Recommendation\"
       else
          grep -P -- \"\\bpam_$l_module_name\\.so\\b\" /etc/authselect/$l_profile_name/{password,system}-auth
       fi
    }
    ```

    _Example output with a custom profile named \"custom-profile\":_

    ```
    /etc/authselect/custom/custom-profile/password-auth:auth   sufficient   pam_unix.so {if not \"without-nullok\":nullok}
    /etc/authselect/custom/custom-profile/password-auth:account   required   pam_unix.so
    /etc/authselect/custom/custom-profile/password-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok
    /etc/authselect/custom/custom-profile/password-auth:session   required   pam_unix.so

    /etc/authselect/custom/custom-profile/system-auth:auth   sufficient   pam_unix.so {if not \"without-nullok\":nullok}
    /etc/authselect/custom/custom-profile/system-auth:account   required   pam_unix.so
    /etc/authselect/custom/custom-profile/system-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok
    /etc/authselect/custom/custom-profile/system-auth:session   required   pam_unix.so
    ```

    - IF - any line is returned with `nullok` that doesn't also include `{if not \"without-nullok\":nullok}`, run the following script:

    ```
    #!/usr/bin/env bash

    {
       for l_pam_file in system-auth password-auth; do
          l_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
          sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_unix\\.so\\s+.*)(nullok)(\\s*.*)$/\\1\\2\\4/g' $l_file
       done
    }
    ```

    - IF - any line is returned with `{if not \"without-nullok\":nullok}`, run the following command to enable the authselect `without-nullok` feature:

    ```
    # authselect enable-feature without-nullok
    ```

    Run the following command to update the files in `/etc/pam.d` to include `pam_unix.so` without the `nullok` argument:

    ```
    # authselect apply-changes
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.3.4.1'
  tag cis_number:            '5.3.3.4.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030401r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- 'pam_unix\.so[^\n]*\bnullok\b' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end