# encoding: UTF-8

control 'C-7.1.13' do
  title 'Ensure SUID and SGID files are reviewed'
  desc  "
    The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID or SGID program is to enable users to perform functions (such as changing their password) that require root privileges.

    There are valid reasons for SUID and SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different checksum than what from the package. This is an indication that the binary may have been replaced.
  "
  desc  'rationale', "
    The owner of a file can set the file's permissions to run with the owner's or group's permissions, even if the user running the program is not the owner or a member of the group. The most common reason for a SUID or SGID program is to enable users to perform functions (such as changing their password) that require root privileges.

    There are valid reasons for SUID and SGID programs, but it is important to identify and review such programs to ensure they are legitimate. Review the files returned by the action in the audit section and check to see if system binaries have a different checksum than what from the package. This is an indication that the binary may have been replaced.
  "
  desc  'check', "
    Run the following script to generate a list of SUID and SGID files:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       a_suid=(); a_sgid=() # initialize arrays
       while IFS= read -r l_mount; do
          while  IFS= read -r -d $'\\0' l_file; do
             if [ -e \"$l_file\" ]; then
                l_mode=\"$(stat -Lc '%#a' \"$l_file\")\"
                [ $(( $l_mode & 04000 )) -gt 0 ] && a_suid+=(\"$l_file\")
                [ $(( $l_mode & 02000 )) -gt 0 ] && a_sgid+=(\"$l_file\")
             fi
          done < <(find \"$l_mount\" -xdev -type f \\( -perm -2000 -o -perm -4000 \\) -print0 2>/dev/null)
       done < <(findmnt -Dkerno fstype,target,options | awk '($1 !~ /^\\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^\\/run\\/user\\// && $3 !~/noexec/ && $3 !~/nosuid/) {print $2}')
       if ! (( ${#a_suid[@]} > 0 )); then
          l_output=\"$l_output\\n - No executable SUID files exist on the system\"
       else
          l_output2=\"$l_output2\\n - List of \\\"$(printf '%s' \"${#a_suid[@]}\")\\\" SUID executable files:\\n$(printf '%s\\n' \"${a_suid[@]}\")\\n - end of list -\\n\"
       fi
       if ! (( ${#a_sgid[@]} > 0 )); then
          l_output=\"$l_output\\n - No SGID files exist on the system\"
       else
          l_output2=\"$l_output2\\n - List of \\\"$(printf '%s' \"${#a_sgid[@]}\")\\\" SGID executable files:\\n$(printf '%s\\n' \"${a_sgid[@]}\")\\n - end of list -\\n\"
       fi
       [ -n \"$l_output2\" ] && l_output2=\"$l_output2\\n- Review the preceding list(s) of SUID and/or SGID files to\\n- ensure that no rogue programs have been introduced onto the system.\\n\" 
       unset a_arr; unset a_suid; unset a_sgid # Remove arrays
       # If l_output2 is empty, Nothing to report
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"$l_output\\n\"
       fi
    }
    ```

    Note: on systems with a large number of files, this may be a long running process
  "
  desc  'fix', "
    Ensure that no rogue SUID or SGID programs have been introduced into the system. Review the files returned by the action in the Audit section and confirm the integrity of these binaries.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.13'
  tag cis_number:            '7.1.13'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070113r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  impact 0.5
  describe 'SUID/SGID file review (7.1.13)' do
    skip 'manual/operational: the inventory of SUID/SGID binaries is host-specific. Operator reviews `find / -xdev -type f \\( -perm -4000 -o -perm -2000 \\)` against the approved baseline.'
  end
end