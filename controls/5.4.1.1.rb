# encoding: UTF-8

control 'C-5.4.1.1' do
  title 'Ensure password expiration is configured'
  desc  "
    The `PASS_MAX_DAYS` parameter in `/etc/login.defs` allows an administrator to force passwords to expire once they reach a defined age.

    `PASS_MAX_DAYS` _ _ - The maximum number of days a password may be used. If the password is older than this, a password change will be forced. If not specified, -1 will be assumed (which disables the restriction).

    The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity.

    We recommend a yearly password change. This is primarily because for all their good intentions users will share credentials across accounts. Therefore, even if a breach is publicly identified, the user may not see this notification, or forget they have an account on that site. This could leave a shared credential vulnerable indefinitely. Having an organizational policy of a 1-year (annual) password expiration is a reasonable compromise to mitigate this with minimal user burden.
  "
  desc  'rationale', "
    The `PASS_MAX_DAYS` parameter in `/etc/login.defs` allows an administrator to force passwords to expire once they reach a defined age.

    `PASS_MAX_DAYS` _ _ - The maximum number of days a password may be used. If the password is older than this, a password change will be forced. If not specified, -1 will be assumed (which disables the restriction).

    The window of opportunity for an attacker to leverage compromised credentials or successfully compromise credentials via an online brute force attack is limited by the age of the password. Therefore, reducing the maximum age of a password also reduces an attacker's window of opportunity.

    We recommend a yearly password change. This is primarily because for all their good intentions users will share credentials across accounts. Therefore, even if a breach is publicly identified, the user may not see this notification, or forget they have an account on that site. This could leave a shared credential vulnerable indefinitely. Having an organizational policy of a 1-year (annual) password expiration is a reasonable compromise to mitigate this with minimal user burden.
  "
  desc  'check', "
    Run the following command and verify `PASS_MAX_DAYS` is set to 365 days or less and conforms to local site policy:

    ```
    # grep -Pi -- '^\\h*PASS_MAX_DAYS\\h+\\d+\\b' /etc/login.defs
    ```

    _Example output:_

    ```
    PASS_MAX_DAYS 365
    ```

    Run the following command to verify all `/etc/shadow` passwords `PASS_MAX_DAYS`:
    - is greater than `0` days
    - is less than or equal to `365` days
    - conforms to local site policy

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($5 > 365 || $5 < 1)print \"User: \" $1 \" PASS_MAX_DAYS: \" $5}' /etc/shadow
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Set the `PASS_MAX_DAYS` parameter to conform to site policy in `/etc/login.defs` :

    ```
    PASS_MAX_DAYS 365
    ```

    Modify user parameters for all users with a password set to match:

    ```
    # chage --maxdays 365 ```

    Edit `/etc/login.defs` and set `PASS_MAX_DAYS` to a value greater than `0` that follows local site policy:

    _Example:_

    ```
    PASS_MAX_DAYS 365
    ```

    Run the following command to modify user parameters for all users with a password set to a maximum age no greater than `365` or less than `1` that follows local site policy:

    ```
    # chage --maxdays ```

    _Example:_

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($5 > 365 || $5 < 1)system (\"chage --maxdays 365 \" $1)}' /etc/shadow
    ```

    Warning: If a password has been set at system install or kickstart, the `last change date` field is not set, In this case, setting `PASS_MAX_DAYS` will immediately expire the password. One possible solution is to populate the `last change date` field through a command like: `chage -d \"$(date +%Y-%m-%d)\" root`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag nist_r4:               ['IA-5 (1) (e)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.4.1.1'
  tag cis_number:            '5.4.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 365 }
  end
end