# encoding: UTF-8

control 'C-5.3.3.4.3' do
  title 'Ensure pam_unix includes a strong password hashing algorithm'
  desc  "
    A cryptographic hash function converts an arbitrary-length input into a fixed length output. Password hashing performs a one-way transformation of a password, turning the password into another string, called the hashed password.

    The `SHA-512` and `yescrypt` algorithms provide a stronger hash than other algorithms used by Linux for password hash generation. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local user passwords.

    Note: These changes only apply to the local system.
  "
  desc  'rationale', "
    A cryptographic hash function converts an arbitrary-length input into a fixed length output. Password hashing performs a one-way transformation of a password, turning the password into another string, called the hashed password.

    The `SHA-512` and `yescrypt` algorithms provide a stronger hash than other algorithms used by Linux for password hash generation. A stronger hash provides additional protection to the system by increasing the level of effort needed for an attacker to successfully determine local user passwords.

    Note: These changes only apply to the local system.
  "
  desc  'check', "
    Run the following command to verify that a strong password hashing algorithm is set on the pam_unix.so module:

    ```
    # grep -P -- '^\\h*password\\h+([^#\\n\\r]+)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(sha512|yescrypt)\\b' /etc/pam.d/{password,system}-auth
    ```

    Output should be similar to:

    ```
    /etc/pam.d/password-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok

    /etc/pam.d/system-auth:password   sufficient   pam_unix.so sha512 shadow  use_authtok
    ```

    Verify that the lines include either `sha512` - OR - `yescrypt`
  "
  desc  'fix', "
    Note: 
    - It is highly recommended that the chosen hashing algorithm is consistent across `/etc/libuser.conf`, `/etc/login.defs`, `/etc/pam.d/password-auth`, and `/etc/pam.d/system-auth`.
    - This only effects local users and passwords created after updating the files to use `sha512` or `yescrypt`. If it is determined that the password algorithm being used is not `sha512` or `yescrypt`, once it is changed, it is recommended that all user ID's be immediately expired and forced to change their passwords on next login.

    Run the following script to verify the active authselect profile includes a strong password hashing algorithm on the password stack's pam_unix.so module lines:

    ```
    #!/usr/bin/env bash

    {
       l_pam_profile=\"$(head -1 /etc/authselect/authselect.conf)\"
       if grep -Pq -- '^custom\\/' <<< \"$l_pam_profile\"; then
          l_pam_profile_path=\"/etc/authselect/$l_pam_profile\"
       else
          l_pam_profile_path=\"/usr/share/authselect/default/$l_pam_profile\"
       fi
       grep -P -- '^\\h*password\\h+(requisite|required|sufficient)\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(sha512|yescrypt)\\b' \"$l_pam_profile_path\"/{password,system}-auth
    }
    ```

    _Example output:_

    ```
    /etc/authselect/custom/custom-profile/password-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok

    /etc/authselect/custom/custom-profile/system-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok
    ```

    - IF - the output does not include either `sha512` - OR - `yescrypt`, or includes a different hashing algorithm, run the following script:

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
          if grep -Pq '^\\h*password\\h+()\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(sha512|yescrypt)\\b' \"$l_authselect_file\"; then
             echo \"- A strong password hashing algorithm is correctly set\"
          elif grep -Pq '^\\h*password\\h+()\\h+pam_unix\\.so\\h+([^#\\n\\r]+\\h+)?(md5|bigcrypt|sha256|blowfish)\\b' \"$l_authselect_file\"; then
             echo \"- A weak password hashing algorithm is set, updating to \\\"sha512\\\"\"
             sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_unix\\.so\\s+.*)(md5|bigcrypt|sha256|blowfish)(\\s*.*)$/\\1\\4 sha512/g' \"$l_authselect_file\"
          else
             echo \"No password hashing algorithm is set, updating to \\\"sha512\\\"\"
             sed -ri 's/(^\\s*password\\s+(requisite|required|sufficient)\\s+pam_unix\\.so\\s+.*)$/& sha512/g' \"$l_authselect_file\"
          fi
       done
    }
    ```

    Run the following command to update the `password-auth` and `system-auth` files in `/etc/pam.d` to include `pam_unix.so` with a strong password hashing algorithm argument:

    ```
    # authselect apply-changes
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'CM-8 a 1']
  tag cci:                   ['CCI-001199', 'CCI-000389']
  tag cis_rid:               '5.3.3.4.3'
  tag cis_number:            '5.3.3.4.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030403r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rP -- 'pam_unix\.so[^\n]*(sha512|yescrypt)' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end