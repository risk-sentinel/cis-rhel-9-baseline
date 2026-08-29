# encoding: UTF-8

control 'C-5.3.2.4' do
  title 'Ensure pam_pwhistory module is enabled'
  desc  "
    The `pam_history.so` module saves the last passwords for each user in order to force password change history and keep the user from alternating between the same password too frequently.

    Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password.
  "
  desc  'rationale', "
    The `pam_history.so` module saves the last passwords for each user in order to force password change history and keep the user from alternating between the same password too frequently.

    Requiring users not to reuse their passwords make it less likely that an attacker will be able to guess the password or use a compromised password.
  "
  desc  'check', "
    Run the following commands to verify that `pam_pwhistory` is enabled:

    ```
    # grep -P -- '\\bpam_pwhistory\\.so\\b' /etc/pam.d/{password,system}-auth
    ```

    Output should be similar to:

    ```
    /etc/pam.d/password-auth:password   required   pam_pwhistory.so use_authtok
    /etc/pam.d/system-auth:password   required   pam_pwhistory.so use_authtok
    ```
  "
  desc  'fix', "
    Run the following script to verify the `pam_pwhistory.so` lines exist in the profile templates:

    ```
    #!/usr/bin/env bash

    {
       l_module_name=\"pwhistory\"
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
    /etc/authselect/custom/custom-profile/password-auth:password   required   pam_pwhistory.so use_authtok {include if \"with-pwhistory\"}

    /etc/authselect/custom/custom-profile/system-auth:password   required   pam_pwhistory.so use_authtok {include if \"with-pwhistory\"}
    ```

    Note: The lines may not include `{include if \"with-pwhistory\"}`

    - IF - the lines shown above are not returned, refer to the Recommendation \"Ensure active authselect profile includes pam modules\" to update the authselect profile template files to include the `pam_pwhistory` entries before continuing this remediation.

    - IF - the lines include `{include if \"with-pwhistory\"}`, run the following command to enable the authselect `with-pwhistory` feature and update the files in `/etc/pam.d` to include `pam_faillock.so`:

    ```
    # authselect enable-feature with-pwhistory
    ```

    - IF - any of the `pam_pwhistory` lines exist without `{include if \"with-pwhistory\"}`, run the following command to update the files in `/etc/pam.d` to include `pam_pwhistory.so`:

    ```
    # authselect apply-changes
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.2.4'
  tag cis_number:            '5.3.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- 'pam_pwhistory\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end