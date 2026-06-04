# encoding: UTF-8

control 'C-5.4.1.2' do
  title 'Ensure minimum password days is configured'
  desc  "
    `PASS_MIN_DAYS` <_N_> - The minimum number of days allowed between password changes. Any password changes attempted sooner than this will be rejected. If not specified, 0 will be assumed (which disables the restriction).

    Users may have favorite passwords that they like to use because they are easy to remember and they believe that their password choice is secure from compromise. Unfortunately, passwords are compromised and if an attacker is targeting a specific individual user account, with foreknowledge of data about that user, reuse of old, potentially compromised passwords, may cause a security breach.

    By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls
  "
  desc  'rationale', "
    `PASS_MIN_DAYS` <_N_> - The minimum number of days allowed between password changes. Any password changes attempted sooner than this will be rejected. If not specified, 0 will be assumed (which disables the restriction).

    Users may have favorite passwords that they like to use because they are easy to remember and they believe that their password choice is secure from compromise. Unfortunately, passwords are compromised and if an attacker is targeting a specific individual user account, with foreknowledge of data about that user, reuse of old, potentially compromised passwords, may cause a security breach.

    By restricting the frequency of password changes, an administrator can prevent users from repeatedly changing their password in an attempt to circumvent password reuse controls
  "
  desc  'check', "
    Run the following command to verify that `PASS_MIN_DAYS` is set to a value greater than `0`and follows local site policy:

    ```
    # grep -Pi -- '^\\h*PASS_MIN_DAYS\\h+\\d+\\b' /etc/login.defs
    ```

    _Example output:_

    ```
    PASS_MIN_DAYS   1
    ```

    Run the following command to verify all passwords have a `PASS_MIN_DAYS` greater than `0`:

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($4 < 1)print \"User: \" $1 \" PASS_MIN_DAYS: \" $4}' /etc/shadow
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Edit `/etc/login.defs` and set `PASS_MIN_DAYS` to a value greater than `0` that follows local site policy:

    _Example:_

    ```
    PASS_MIN_DAYS 1
    ```

    Run the following command to modify user parameters for all users with a password set to a minimum days greater than zero that follows local site policy:

    ```
    # chage --mindays ```

    _Example:_

    ```
    # awk -F: '($2~/^\\$.+\\$/) {if($4 < 1)system (\"chage --mindays 1 \" $1)}' /etc/shadow
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.4.1.2'
  tag cis_number:            '5.4.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe login_defs do
    its('PASS_MIN_DAYS') { should cmp >= 1 }
  end
end