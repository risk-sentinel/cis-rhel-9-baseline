# encoding: UTF-8

control 'C-7.1.12' do
  title 'Ensure no files or directories without an owner and a group exist'
  desc  "
    Administrators may delete users or groups from the system and neglect to remove all files and/or directories owned by those users or groups.

    A new user or group who is assigned a deleted user's user ID or group ID may then end up \"owning\" a deleted user or group's files, and thus have more access on the system than was intended.
  "
  desc  'rationale', "
    Administrators may delete users or groups from the system and neglect to remove all files and/or directories owned by those users or groups.

    A new user or group who is assigned a deleted user's user ID or group ID may then end up \"owning\" a deleted user or group's files, and thus have more access on the system than was intended.
  "
  desc  'check', "
    Run the following script to verify no unowned or ungrouped files or directories exist:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       a_nouser=(); a_nogroup=() # Initialize arrays
       a_path=(! -path \"/run/user/*\" -a ! -path \"/proc/*\" -a ! -path \"*/containerd/*\" -a ! -path \"*/kubelet/pods/*\" -a ! -path \"*/kubelet/plugins/*\" -a ! -path \"/sys/fs/cgroup/memory/*\" -a ! -path \"/var/*/private/*\")
       while IFS= read -r l_mount; do
          while IFS= read -r -d $'\\0' l_file; do
             if [ -e \"$l_file\" ]; then
                while IFS=: read -r l_user l_group; do
                   [ \"$l_user\" = \"UNKNOWN\" ] && a_nouser+=(\"$l_file\")
                   [ \"$l_group\" = \"UNKNOWN\" ] && a_nogroup+=(\"$l_file\")
                done < <(stat -Lc '%U:%G' \"$l_file\")
             fi
          done < <(find \"$l_mount\" -xdev \\( \"${a_path[@]}\" \\) \\( -type f -o -type d \\) \\( -nouser -o -nogroup \\) -print0 2> /dev/null)
       done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\\/run\\/user\\//){print $2}')
       if ! (( ${#a_nouser[@]} > 0 )); then
          l_output=\"$l_output\\n  - No files or directories without a owner exist on the local filesystem.\"
       else
          l_output2=\"$l_output2\\n  - There are \\\"$(printf '%s' \"${#a_nouser[@]}\")\\\" unowned files or directories on the system.\\n   - The following is a list of unowned files and/or directories:\\n$(printf '%s\\n' \"${a_nouser[@]}\")\\n   - end of list\"
       fi
       if ! (( ${#a_nogroup[@]} > 0 )); then
          l_output=\"$l_output\\n  - No files or directories without a group exist on the local filesystem.\"
       else
          l_output2=\"$l_output2\\n  - There are \\\"$(printf '%s' \"${#a_nogroup[@]}\")\\\" ungrouped files or directories on the system.\\n   - The following is a list of ungrouped files and/or directories:\\n$(printf '%s\\n' \"${a_nogroup[@]}\")\\n   - end of list\"
       fi 
       unset a_path; unset a_arr ; unset a_nouser; unset a_nogroup # Remove arrays
       if [ -z \"$l_output2\" ]; then # If l_output2 is empty, we pass
          echo -e \"\\n- Audit Result:\\n   PASS \\n - * Correctly configured * :\\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :\\n$l_output2\"
          [ -n \"$l_output\" ] && echo -e \"\\n- * Correctly configured * :\\n$l_output\\n\"
       fi
    }
    ```

    Note: On systems with a large number of files and/or directories, this audit may be a long running process
  "
  desc  'fix', "
    Remove or set ownership and group ownership of these files and/or directories to an active user on the system as appropriate.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.12'
  tag cis_number:            '7.1.12'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070112r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{find / -xdev \( -nouser -o -nogroup \) 2>/dev/null}) do
    its('stdout') { should be_empty }
  end
end