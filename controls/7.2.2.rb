# encoding: UTF-8

control 'C-7.2.2' do
  title 'Ensure /etc/shadow password fields are not empty'
  desc  "
    An account with an empty password field means that anybody may log in as that user without providing a password.

    All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
  "
  desc  'rationale', "
    An account with an empty password field means that anybody may log in as that user without providing a password.

    All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
  "
  desc  'check', "
    Run the following command and verify that no output is returned:

    ```
    # awk -F: '($2 == \"\" ) { print $1 \" does not have a password \"}' /etc/shadow
    ```
  "
  desc  'fix', "
    If any accounts in the `/etc/shadow` file do not have a password, run the following command to lock the account until it can be determined why it does not have a password:

    ```
    # passwd -l ```

    Also, check to see if the account is logged in and investigate what it is being used for to determine if it needs to be forced off.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '7.2.2'
  tag cis_number:            '7.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure /etc/shadow password fields are not empty' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070202r1_rule.'
  end
end
