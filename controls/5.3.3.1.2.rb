# encoding: UTF-8

control 'C-5.3.3.1.2' do
  title 'Ensure password unlock time is configured'
  desc  "
    `unlock_time= ` - The access will be re-enabled after _ _ seconds after the lock out. The value `0` has the same meaning as value never - the access will not be re-enabled without resetting the faillock entries by the faillock(8) command.

    Notes:
    - The default directory that pam_faillock uses is usually cleared on system boot so the access will be also re-enabled after system reboot. If that is undesirable a different tally directory must be set with the dir option.
    - It is usually undesirable to permanently lock out users as they can become easily a target of denial of service attack unless the usernames are random and kept secret to potential attackers.
    - The maximum configurable value for `unlock_time` is `604800`

    Locking out user IDs after _n_ unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'rationale', "
    `unlock_time= ` - The access will be re-enabled after _ _ seconds after the lock out. The value `0` has the same meaning as value never - the access will not be re-enabled without resetting the faillock entries by the faillock(8) command.

    Notes:
    - The default directory that pam_faillock uses is usually cleared on system boot so the access will be also re-enabled after system reboot. If that is undesirable a different tally directory must be set with the dir option.
    - It is usually undesirable to permanently lock out users as they can become easily a target of denial of service attack unless the usernames are random and kept secret to potential attackers.
    - The maximum configurable value for `unlock_time` is `604800`

    Locking out user IDs after _n_ unsuccessful consecutive login attempts mitigates brute force password attacks against your systems.
  "
  desc  'check', "
    Run the following command to verify that the time in seconds before the account is unlocked is either `0` (never) or `900` (15 minutes) or more and meets local site policy:

    ```
    # grep -Pi -- '^\\h*unlock_time\\h*=\\h*(0|9[0-9][0-9]|[1-9][0-9]{3,})\\b' /etc/security/faillock.conf

    unlock_time = 900
    ```

    Run the following command to verify that the `unlock_time` argument has not been set, or is either `0` (never) or `900` (15 minutes) or more and meets local site policy:

    ```
    # grep -Pi -- '^\\h*auth\\h+(requisite|required|sufficient)\\h+pam_faillock\\.so\\h+([^#\\n\\r]+\\h+)?unlock_time\\h*=\\h*([1-9]|[1-9][0-9]|[1-8][0-9][0-9])\\b' /etc/pam.d/system-auth /etc/pam.d/password-auth

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Set password unlock time to conform to site policy. `unlock_time` should be `0` (never), or `900` seconds or greater.

    Edit `/etc/security/faillock.conf` and update or add the following line:

    ```
    unlock_time = 900
    ```

    Run the following script to remove the `unlock_time` argument from the `pam_faillock.so` module in the PAM files:

    ```
    #!/usr/bin/env bash
    {
       for l_pam_file in system-auth password-auth; do
         l_authselect_file=\"/etc/authselect/$(head -1 /etc/authselect/authselect.conf | grep 'custom/')/$l_pam_file\"
         sed -ri 's/(^\\s*auth\\s+(requisite|required|sufficient)\\s+pam_faillock\\.so.*)(\\s+unlock_time\\s*=\\s*\\S+)(.*$)/\\1\\4/' \"$l_authselect_file\"
       done
       authselect apply-changes
    }
    ``
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'CM-6 a']
  tag cci:                   ['CCI-000011', 'CCI-000363']
  tag cis_rid:               '5.3.3.1.2'
  tag cis_number:            '5.3.3.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0503030102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -P -- '^\h*unlock_time\h*=' /etc/security/faillock.conf}) do
    its('stdout') { should match(/\S/) }
  end
end