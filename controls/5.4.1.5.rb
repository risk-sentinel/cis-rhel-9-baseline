# encoding: UTF-8

control 'C-5.4.1.5' do
  title 'Ensure inactive password lock is configured'
  desc  "
    User accounts that have been inactive for over a given period of time can be automatically disabled.

    `INACTIVE` - Defines the number of days after the password exceeded its maximum age where the user is expected to replace this password.

    The value is stored in the shadow password file. An input of `0` will disable an expired password with no delay. An input of `-1` will blank the respective field in the shadow password file.

    Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies.
  "
  desc  'rationale', "
    User accounts that have been inactive for over a given period of time can be automatically disabled.

    `INACTIVE` - Defines the number of days after the password exceeded its maximum age where the user is expected to replace this password.

    The value is stored in the shadow password file. An input of `0` will disable an expired password with no delay. An input of `-1` will blank the respective field in the shadow password file.

    Inactive accounts pose a threat to system security since the users are not logging in to notice failed login attempts or other anomalies.
  "
  desc  'check', "
    Run the following command and verify `INACTIVE` conforms to site policy (no more than 45 days):

    ```
    # useradd -D | grep INACTIVE

    INACTIVE=45
    ```

    Verify all users with a password have Password inactive no more than 45 days after password expires

    Verify all users with a password have Password inactive no more than 45 days after password expires: Run the following command and Review list of users and `INACTIVE` to verify that all users `INACTIVE` conforms to site policy (no more than 45 days):

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($7 > 45 || $7 < 0)print \"User: \" $1 \" INACTIVE: \" $7}' /etc/shadow
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Run the following command to set the default password inactivity period to 45 days or less that meets local site policy:

    ```
    # useradd -D -f ```

    _Example:_

    ```
    # useradd -D -f 45
    ```

    Run the following command to modify user parameters for all users with a password set to a inactive age of `45` days or less that follows local site policy:

    ```
    # chage --inactive ```

    _Example:_

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($7 > 45 || $7 < 0)system (\"chage --inactive 45 \" $1)}' /etc/shadow
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.4.1.5'
  tag cis_number:            '5.4.1.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040105r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{useradd -D 2>/dev/null}) do
    its('stdout') { should match(/INACTIVE=(30|[12]?[0-9])\b/) }
  end
end