# encoding: UTF-8

control 'C-5.3.3.1.1' do
  title 'Ensure password failed attempts lockout is configured'
  desc  "
    The `deny= ` option will deny access if the number of consecutive authentication failures for this user during the recent interval exceeds _ _.

    Locking out user IDs after _n_ unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'rationale', "
    The `deny= ` option will deny access if the number of consecutive authentication failures for this user during the recent interval exceeds _ _.

    Locking out user IDs after _n_ unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'check', "
    Run the following command to verify that Number of failed logon attempts before the account is locked is no greater than `5` and meets local site policy:

    ```
    # grep -Pi -- '^\\h*deny\\h*=\\h*[1-5]\\b' /etc/security/faillock.conf

    deny = 5
    ```

    Run the following command to verify that the `deny` argument has not been set, or is set to 5 or less and meets local site policy:

    ```
    # grep -Pi -- '^\\h*auth\\h+(requisite|required|sufficient)\\h+pam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?deny\\h*=\\h*(0|[6-9]|[1-9][0-9]+)\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Create or edit the following line in `/etc/security/faillock.conf` setting the `deny` option to `5` or less:

    ```
    deny = 5
    ```

    Run the following script to remove the `deny` argument from the `pam_faillock.so` module in the PAM files:

    ```
    #!/usr/bin/env bash
    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*auth\\s+(requisite|required|sufficient)\\s+pam_faillock\\.so.*)(\\s+deny\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
       done
       authselect apply-changes
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'CM-6 a']
  tag cci:                   ['CCI-000011', 'CCI-000363']
  tag cis_rid:               '5.3.3.1.1'
  tag cis_number:            '5.3.3.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -P -- '^\h*deny\h*=' /etc/security/faillock.conf}) do
    its('stdout') { should match(/\S/) }
  end
end