# encoding: UTF-8

control 'C-7.2.3' do
  title 'Ensure all groups in /etc/passwd exist in /etc/group'
  desc  "
    Over time, system administration errors and changes can lead to groups being defined in `/etc/passwd` but not in `/etc/group` .

    Groups defined in the `/etc/passwd` file but not in the `/etc/group` file pose a threat to system security since group permissions are not properly managed.
  "
  desc  'rationale', "
    Over time, system administration errors and changes can lead to groups being defined in `/etc/passwd` but not in `/etc/group` .

    Groups defined in the `/etc/passwd` file but not in the `/etc/group` file pose a threat to system security since group permissions are not properly managed.
  "
  desc  'check', "
    Run the following script to verify all GIDs in `/etc/passwd` exist in `/etc/group`:

    ```
    #!/usr/bin/env bash

    {
       a_passwd_group_gid=(\"$(awk -F: '{print $4}' /etc/passwd | sort -u)\")
       a_group_gid=(\"$(awk -F: '{print $3}' /etc/group | sort -u)\")
       a_passwd_group_diff=(\"$(printf '%s\\n' \"${a_group_gid[@]}\" \"${a_passwd_group_gid[@]}\" | sort | uniq -u)\")
       while IFS= read -r l_gid; do
          awk -F: '($4 == '\"$l_gid\"') {print \"  - User: \\\"\" $1 \"\\\" has GID: \\\"\" $4 \"\\\" which does not exist in /etc/group\" }' /etc/passwd
       done < <(printf '%s\\n' \"${a_passwd_group_gid[@]}\" \"${a_passwd_group_diff[@]}\" | sort | uniq -D | uniq)
       unset a_passwd_group_gid; unset a_group_gid; unset a_passwd_group_diff
    }
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Analyze the output of the Audit step above and perform the appropriate action to correct any discrepancies found.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.2.3'
  tag cis_number:            '7.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure all groups in /etc/passwd exist in /etc/group' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070203r1_rule.'
  end
end
