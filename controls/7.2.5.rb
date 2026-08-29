# encoding: UTF-8

control 'C-7.2.5' do
  title 'Ensure no duplicate GIDs exist'
  desc  "
    Although the `groupadd` program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the `/etc/group` file and change the GID field.

    User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
  "
  desc  'rationale', "
    Although the `groupadd` program will not let you create a duplicate Group ID (GID), it is possible for an administrator to manually edit the `/etc/group` file and change the GID field.

    User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
  "
  desc  'check', "
    Run the following script and verify no results are returned:

    ```
    #!/usr/bin/env bash

    {
       while read -r l_count l_gid; do
          if [ \"$l_count\" -gt 1 ]; then
          echo -e \"Duplicate GID: \\\"$l_gid\\\" Groups: \\\"$(awk -F: '($3 == n) { print $1 }' n=$l_gid /etc/group | xargs)\\\"\"
        fi
      done < <(cut -f3 -d\":\" /etc/group | sort -n | uniq -c)
    } 
    ```
  "
  desc  'fix', "
    Based on the results of the audit script, establish unique GIDs and review all files owned by the shared GID to determine which group they are supposed to belong to.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '7.2.5'
  tag cis_number:            '7.2.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070205r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{cut -d: -f3 /etc/group | sort -n | uniq -d}) do
    its('stdout') { should be_empty }
  end
end