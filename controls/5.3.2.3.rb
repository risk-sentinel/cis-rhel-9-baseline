# encoding: UTF-8

control 'C-5.3.2.3' do
  title 'Ensure pam_pwquality module is enabled'
  desc  "
    The `pam_pwquality.so` module performs password quality checking. This module can be plugged into the password stack of a given service to provide strength-checking for passwords. The code was originally based on pam_cracklib module and the module is backwards compatible with its options. 

    The action of this module is to prompt the user for a password and check its strength against a system dictionary and a set of rules for identifying poor choices.

    The first action is to prompt for a single password, check its strength and then, if it is considered strong, prompt for the password a second time (to verify that it was typed correctly on the first occasion). All being well, the password is passed on to subsequent modules to be installed as the new authentication token.

    Use of a unique, complex passwords helps to increase the time and resources required to compromise the password.
  "
  desc  'rationale', "
    The `pam_pwquality.so` module performs password quality checking. This module can be plugged into the password stack of a given service to provide strength-checking for passwords. The code was originally based on pam_cracklib module and the module is backwards compatible with its options. 

    The action of this module is to prompt the user for a password and check its strength against a system dictionary and a set of rules for identifying poor choices.

    The first action is to prompt for a single password, check its strength and then, if it is considered strong, prompt for the password a second time (to verify that it was typed correctly on the first occasion). All being well, the password is passed on to subsequent modules to be installed as the new authentication token.

    Use of a unique, complex passwords helps to increase the time and resources required to compromise the password.
  "
  desc  'check', "
    Run the following commands to verify that `pam_pwquality` is enabled:

    ```
    # grep -P -- '\\bpam_pwquality\\.so\\b' /etc/pam.d/{password,system}-auth
    ```

    Output should be similar to:

    ```
    /etc/pam.d/password-auth:password   requisite   pam_pwquality.so local_users_only
    /etc/pam.d/system-auth:password   requisite   pam_pwquality.so local_users_only
    ```
  "
  desc  'fix', "
    Review the authselect profile templates:

    Run the following script to verify the `pam_pwquality.so` lines exist in the active profile templates:

    ```
    #!/usr/bin/env bash

    {
       l_module_name=\"pwquality\"
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
    /etc/authselect/custom/custom-profile/password-auth:password   requisite   pam_pwquality.so local_users_only {include if \"with-pwquality\"}

    /etc/authselect/custom/custom-profile/system-auth:password   requisite   pam_pwquality.so local_users_only {include if \"with-pwquality\"}
    ```

    Note: The lines may not include `{include if \"with-pwquality\"}`

    - IF - the lines shown above are not returned, refer to the Recommendation \"Ensure active authselect profile includes pam modules\" to update the authselect profile template files to include the `pam_pwquality` entries before continuing this remediation.	

    - IF - any of the `pam_pwquality` lines include `{include if \"with-pwquality\"}`, run the following command to enable the authselect `with-pwquality` feature and update the files in `/etc/pam.d` to include `pam_pwquality:

    ```
    # authselect enable-feature with-pwquality
    ```

    - IF - any of the `pam_pwquality` lines exist without `{include if \"with-pwquality\"}`, run the following command to update the files in `/etc/pam.d` to include `pam_pwquality.so`:

    ```
    # authselect apply-changes
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-IAM-APM', 'KSI-SVC-EIS']
  tag nist_r4:               ['IA-5 (1) (e)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.3.2.3'
  tag cis_number:            '5.3.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- 'pam_pwquality\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end