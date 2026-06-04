# encoding: UTF-8

control 'C-7.2.6' do
  title 'Ensure no duplicate user names exist'
  desc  "
    Although the `useradd` program will not let you create a duplicate user name, it is possible for an administrator to manually edit the `/etc/passwd` file and change the user name.

    If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in `/etc/passwd` . For example, if \"test4\" has a UID of 1000 and a subsequent \"test4\" entry has a UID of 2000, logging in as \"test4\" will use UID 1000. Effectively, the UID is shared, which is a security problem.
  "
  desc  'rationale', "
    Although the `useradd` program will not let you create a duplicate user name, it is possible for an administrator to manually edit the `/etc/passwd` file and change the user name.

    If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that username in `/etc/passwd` . For example, if \"test4\" has a UID of 1000 and a subsequent \"test4\" entry has a UID of 2000, logging in as \"test4\" will use UID 1000. Effectively, the UID is shared, which is a security problem.
  "
  desc  'check', "
    Run the following script and verify no results are returned:

    ```
    #!/usr/bin/env bash

    {
       while read -r l_count l_user; do
          if [ \"$l_count\" -gt 1 ]; then
             echo -e \"Duplicate User: \\\"$l_user\\\" Users: \\\"$(awk -F: '($1 == n) { print $1 }' n=$l_user /etc/passwd | xargs)\\\"\"
          fi
       done < <(cut -f1 -d\":\" /etc/group | sort -n | uniq -c)
    }
    ```
  "
  desc  'fix', "
    Based on the results of the audit script, establish unique user names for the users. File ownerships will automatically reflect the change as long as the users have unique UIDs.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '7.2.6'
  tag cis_number:            '7.2.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070206r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure no duplicate user names exist' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070206r1_rule.'
  end
end
