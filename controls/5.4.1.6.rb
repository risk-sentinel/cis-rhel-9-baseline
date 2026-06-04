# encoding: UTF-8

control 'C-5.4.1.6' do
  title 'Ensure all users last password change date is in the past'
  desc  "
    All users should have a password change date in the past.

    If a user's recorded password change date is in the future, then they could bypass any set password expiration.
  "
  desc  'rationale', "
    All users should have a password change date in the past.

    If a user's recorded password change date is in the future, then they could bypass any set password expiration.
  "
  desc  'check', "
    Run the following script and verify nothing is returned:

    ```
    #!/usr/bin/env bash

    {
       while IFS= read -r l_user; do
          l_change=$(date -d \"$(chage --list $l_user | grep '^Last password change' | cut -d: -f2 | grep -v 'never$')\" +%s)
          if [[ \"$l_change\" -gt \"$(date +%s)\" ]]; then
             echo \"User: \\\"$l_user\\\" last password change was \\\"$(chage --list $l_user | grep '^Last password change' | cut -d: -f2)\\\"\"
          fi
       done < <(awk -F: '$2~/^\\$.+\\$/{print $1}' /etc/shadow)
    }
    ```
  "
  desc  'fix', "
    Investigate any users with a password change date in the future and correct them.  Locking the account, expiring the password, or resetting the password manually may be appropriate.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.4.1.6'
  tag cis_number:            '5.4.1.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040106r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure all users last password change date is in the past' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-05040106r1_rule.'
  end
end
