# encoding: UTF-8

control 'C-7.2.7' do
  title 'Ensure no duplicate group names exist'
  desc  "
    Although the `groupadd` program will not let you create a duplicate group name, it is possible for an administrator to manually edit the `/etc/group` file and change the group name.

    If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in `/etc/group` . Effectively, the GID is shared, which is a security problem.
  "
  desc  'rationale', "
    Although the `groupadd` program will not let you create a duplicate group name, it is possible for an administrator to manually edit the `/etc/group` file and change the group name.

    If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that group in `/etc/group` . Effectively, the GID is shared, which is a security problem.
  "
  desc  'check', "
    Run the following script and verify no results are returned:

    ```
    #!/usr/bin/env bash

    {
       while read -r l_count l_group; do
          if [ \"$l_count\" -gt 1 ]; then
             echo -e \"Duplicate Group: \\\"$l_group\\\" Groups: \\\"$(awk -F: '($1 == n) { print $1 }' n=$l_group /etc/group | xargs)\\\"\"
          fi
       done < <(cut -f1 -d\":\" /etc/group | sort -n | uniq -c)
    }
    ```
  "
  desc  'fix', "
    Based on the results of the audit script, establish unique names for the user groups. File group ownerships will automatically reflect the change as long as the groups have unique GIDs.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '7.2.7'
  tag cis_number:            '7.2.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070207r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{cut -d: -f1 /etc/group | sort | uniq -d}) do
    its('stdout') { should be_empty }
  end
end