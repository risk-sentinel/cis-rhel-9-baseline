# encoding: UTF-8

control 'C-5.4.1.3' do
  title 'Ensure password expiration warning days is configured'
  desc  "
    The `PASS_WARN_AGE` parameter in `/etc/login.defs`  allows an administrator to notify users that their password will expire in a defined number of days.

    `PASS_WARN_AGE` _ _ - The number of days warning given before a password expires. A zero means warning is given only upon the day of expiration, a negative value means no warning is given. If not specified, no warning will be provided.

    Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered.
  "
  desc  'rationale', "
    The `PASS_WARN_AGE` parameter in `/etc/login.defs`  allows an administrator to notify users that their password will expire in a defined number of days.

    `PASS_WARN_AGE` _ _ - The number of days warning given before a password expires. A zero means warning is given only upon the day of expiration, a negative value means no warning is given. If not specified, no warning will be provided.

    Providing an advance warning that a password will be expiring gives users time to think of a secure password. Users caught unaware may choose a simple password or write it down where it may be discovered.
  "
  desc  'check', "
    Run the following command and verify `PASS_WARN_AGE` is `7` or more and follows local site policy:

    ```
    # grep -Pi -- '^\\h*PASS_WARN_AGE\\h+\\d+\\b' /etc/login.defs
    ```

    _Example output:_

    ```
    PASS_WARN_AGE 7
    ```

    Run the following command to verify all passwords have a `PASS_WARN_AGE` of `7` or more:

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($6 < 7)print \"User: \" $1 \" PASS_WARN_AGE: \" $6}' /etc/shadow
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Edit `/etc/login.defs` and set `PASS_WARN_AGE` to a value of `7` or more that follows local site policy:

    _Example:_

    ```
    PASS_WARN_AGE 7
    ```

    Run the following command to modify user parameters for all users with a password set to a minimum warning to `7` or more days that follows local site policy:

    ```
    # chage --warndays ```

    _Example:_

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($6 < 7)system (\"chage --warndays 7 \" $1)}' /etc/shadow
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 a', 'SC-7 a']
  tag cci:                   ['CCI-000364', 'CCI-001097']
  tag cis_rid:               '5.4.1.3'
  tag cis_number:            '5.4.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe login_defs do
    its('PASS_WARN_AGE') { should cmp >= 7 }
  end
end