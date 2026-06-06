# encoding: UTF-8

control 'C-7.2.4' do
  title 'Ensure no duplicate UIDs exist'
  desc  "
    Although the `useradd` program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the `/etc/passwd` file and change the UID field.

    Users must be assigned unique UIDs for accountability and to ensure appropriate access protections.
  "
  desc  'rationale', "
    Although the `useradd` program will not let you create a duplicate User ID (UID), it is possible for an administrator to manually edit the `/etc/passwd` file and change the UID field.

    Users must be assigned unique UIDs for accountability and to ensure appropriate access protections.
  "
  desc  'check', "
    Run the following script and verify no results are returned:

    ```
    #!/usr/bin/env bash

    {
      while read -r l_count l_uid; do
        if [ \"$l_count\" -gt 1 ]; then
          echo -e \"Duplicate UID: \\\"$l_uid\\\" Users: \\\"$(awk -F: '($3 == n) { print $1 }' n=$l_uid /etc/passwd | xargs)\\\"\"
        fi
      done < <(cut -f3 -d\":\" /etc/passwd | sort -n | uniq -c)
    }
    ```
  "
  desc  'fix', "
    Based on the results of the audit script, establish unique UIDs and review all files owned by the shared UIDs to determine which UID they are supposed to belong to.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '7.2.4'
  tag cis_number:            '7.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{cut -d: -f3 /etc/passwd | sort -n | uniq -d}) do
    its('stdout') { should be_empty }
  end
end