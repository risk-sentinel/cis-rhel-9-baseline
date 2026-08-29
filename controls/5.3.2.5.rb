# encoding: UTF-8

control 'C-5.3.2.5' do
  title 'Ensure pam_unix module is enabled'
  desc  "
    The `pam_unix.so` module is the standard Unix authentication module. It uses standard calls from the system's libraries to retrieve and set account information as well as authentication. Usually this is obtained from the `/etc/passwd` and the `/etc/shadow` file as well if shadow is enabled.

    Requiring users to use authentication make it less likely that an attacker will be able to access the system.
  "
  desc  'rationale', "
    The `pam_unix.so` module is the standard Unix authentication module. It uses standard calls from the system's libraries to retrieve and set account information as well as authentication. Usually this is obtained from the `/etc/passwd` and the `/etc/shadow` file as well if shadow is enabled.

    Requiring users to use authentication make it less likely that an attacker will be able to access the system.
  "
  desc  'check', "
    Run the following commands to verify that `pam_unix` is enabled:

    ```
    # grep -P -- '\\bpam_unix\\.so\\b' /etc/pam.d/{password,system}-auth
    ```

    Output should be similar to:

    ```
    /etc/pam.d/password-auth:auth   sufficient   pam_unix.so
    /etc/pam.d/password-auth:account   required   pam_unix.so
    /etc/pam.d/password-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok
    /etc/pam.d/password-auth:session  required   pam_unix.so

    /etc/pam.d/system-auth:auth   sufficient   pam_unix.so
    /etc/pam.d/system-auth:account   required   pam_unix.so
    /etc/pam.d/system-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok
    /etc/pam.d/system-auth:session   required   pam_unix.so
    ```
  "
  desc  'fix', "
    Run the following script to verify the `pam_unix.so` lines exist in the profile templates:

    ```
    #!/usr/bin/env bash

    {
       l_module_name=\"unix\"
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
    /etc/authselect/custom/custom-profile/password-auth:auth   sufficient   pam_unix.so {if not \"without-nullok\":nullok}
    /etc/authselect/custom/custom-profile/password-auth:account   required   pam_unix.so
    /etc/authselect/custom/custom-profile/password-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok remember=5
    /etc/authselect/custom/custom-profile/password-auth:session   required   pam_unix.so

    /etc/authselect/custom/custom-profile/system-auth:auth   sufficient   pam_unix.so {if not \"without-nullok\":nullok}
    /etc/authselect/custom/custom-profile/system-auth:account   required   pam_unix.so
    /etc/authselect/custom/custom-profile/system-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok
    /etc/authselect/custom/custom-profile/system-auth:session   required   pam_unix.so
    ```

    - IF - the lines shown above are not returned, refer to the Recommendation \"Ensure active authselect profile includes pam modules\" to update the authselect profile template files to include the `pam_unix` entries before continuing this remediation.

    Note: Arguments following `pam_unix.so` may be different than the example output
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.3.2.5'
  tag cis_number:            '5.3.2.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030205r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- 'pam_unix\.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end