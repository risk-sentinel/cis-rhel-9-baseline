# encoding: UTF-8

control 'C-5.3.2.2' do
  title 'Ensure pam_faillock module is enabled'
  desc  "
    The `pam_faillock.so` module maintains a list of failed authentication attempts per user during a specified interval and locks the account in case there were more than the configured number of consecutive failed authentications (this is defined by the `deny` parameter in the faillock configuration). It stores the failure records into per-user files in the tally directory.

    Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'rationale', "
    The `pam_faillock.so` module maintains a list of failed authentication attempts per user during a specified interval and locks the account in case there were more than the configured number of consecutive failed authentications (this is defined by the `deny` parameter in the faillock configuration). It stores the failure records into per-user files in the tally directory.

    Locking out user IDs after n unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'check', "
    Run the following commands to verify that `pam_faillock` is enabled

    ```
    # grep -P -- '\\bpam_faillock.so\\b' /etc/pam.d/{password,system}-auth
    ```

    Output should be similar to:

    ```
    /etc/pam.d/password-auth:auth        required        pam_faillock.so preauth silent
    /etc/pam.d/password-auth:auth        required        pam_faillock.so authfail

    /etc/pam.d/password-auth:account     required        pam_faillock.so

    /etc/pam.d/system-auth:auth          required        pam_faillock.so preauth silent
    /etc/pam.d/system-auth:auth          required        pam_faillock.so authfail

    /etc/pam.d/system-auth:account       required        pam_faillock.so
    ```
  "
  desc  'fix', "
    Run the following script to verify the `pam_faillock.so` lines exist in the profile templates:

    ```
    #!/usr/bin/env bash

    {
       l_module_name=\"faillock\"
       l_pam_profile=\"$(head -1 /etc/authselect/authselect.conf)\"
       if grep -Pq -- '^custom\\/' <<< \"$l_pam_profile\"; then
          l_pam_profile_path=\"/etc/authselect/$l_pam_profile\"
       else
          l_pam_profile_path=\"/usr/share/authselect/default/$l_pam_profile\"
       fi
       grep -P -- \"\\bpam_$l_module_name\\.so\\b\" \"$l_pam_profile_path\"/{password,system}-auth
    }
    ```

    _Example Output with a custom profile named \"custom-profile\":_

    ```
    /etc/authselect/custom/custom-profile/password-auth:auth   required   pam_faillock.so preauth silent {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/password-auth:auth   required   pam_faillock.so authfail {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/password-auth:account   required   pam_faillock.so {include if \"with-faillock\"}

    /etc/authselect/custom/custom-profile/system-auth:auth   required   pam_faillock.so preauth silent {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/system-auth:auth   required   pam_faillock.so authfail {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/system-auth:account   required   pam_faillock.so  {include if \"with-faillock\"}
    ```

    Note: The lines may not include `{include if \"with-faillock\"}`

    - IF - the lines shown above are not returned, refer to the Recommendation \"Ensure active authselect profile includes pam modules\" to update the authselect profile template files to include the `pam_faillock` entries before continuing this remediation.

    - IF - the lines include `{include if \"with-faillock\"}`, run the following command to enable the authselect `with-faillock` feature and update the files in `/etc/pam.d` to include `pam_faillock.so`:

    ```
    # authselect enable-feature with-faillock
    ```

    - IF - any of the `pam_faillock` lines exist without `{include if \"with-faillock\"}`, run the following command to update the files in `/etc/pam.d` to include `pam_faillock.so`:

    ```
    # authselect apply-changes
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 a']
  tag cci:                   ['CCI-000364', 'CCI-000363']
  tag cis_rid:               '5.3.2.2'
  tag cis_number:            '5.3.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- 'pam_faillock\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end