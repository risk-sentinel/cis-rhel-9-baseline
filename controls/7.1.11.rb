# encoding: UTF-8

control 'C-7.1.11' do
  title 'Ensure world writable files and directories are secured'
  desc  "
    World writable files are the least secure. Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity. See the `chmod(2)` man page for more information.

    Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.

    Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity.

    This feature prevents the ability to delete or rename files in world writable directories (such as `/tmp` ) that are owned by another user.
  "
  desc  'rationale', "
    World writable files are the least secure. Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity. See the `chmod(2)` man page for more information.

    Setting the sticky bit on world writable directories prevents users from deleting or renaming files in that directory that are not owned by them.

    Data in world-writable files can be modified and compromised by any user on the system. World writable files may also indicate an incorrectly written script or program that could potentially be the cause of a larger compromise to the system's integrity.

    This feature prevents the ability to delete or rename files in world writable directories (such as `/tmp` ) that are owned by another user.
  "
  desc  'check', "
    Run the following script to verify:
    - No world writable files exist
    - No world writable directories without the sticky bit exist

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       l_smask='01000'
       a_file=(); a_dir=() # Initialize arrays
       a_path=(! -path \"/run/user/*\" -a ! -path \"/proc/*\" -a ! -path \"*/containerd/*\" -a ! -path \"*/kubelet/pods/*\" -a ! -path \"*/kubelet/plugins/*\" -a ! -path \"/sys/*\" -a ! -path \"/snap/*\")
       while IFS= read -r l_mount; do
          while IFS= read -r -d $'\\0' l_file; do
             if [ -e \"$l_file\" ]; then
                [ -f \"$l_file\" ] && a_file+=(\"$l_file\") # Add WR files
                if [ -d \"$l_file\" ]; then # Add directories w/o sticky bit
                   l_mode=\"$(stat -Lc '%#a' \"$l_file\")\"
                   [ ! $(( $l_mode & $l_smask )) -gt 0 ] && a_dir+=(\"$l_file\")
                fi
             fi
          done < <(find \"$l_mount\" -xdev \\( \"${a_path[@]}\" \\) \\( -type f -o -type d \\) -perm -0002 -print0 2> /dev/null)
       done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\\/run\\/user\\/|\\/tmp|\\/var\\/tmp)/){print $2}')
       if ! (( ${#a_file[@]} > 0 )); then
          l_output=\"$l_output\\n  - No world writable files exist on the local filesystem.\"
       else
          l_output2=\"$l_output2\\n - There are \\\"$(printf '%s' \"${#a_file[@]}\")\\\" World writable files on the system.\\n   - The following is a list of World writable files:\\n$(printf '%s\\n' \"${a_file[@]}\")\\n   - end of list\\n\"
       fi
       if ! (( ${#a_dir[@]} > 0 )); then
          l_output=\"$l_output\\n  - Sticky bit is set on world writable directories on the local filesystem.\"
       else
          l_output2=\"$l_output2\\n - There are \\\"$(printf '%s' \"${#a_dir[@]}\")\\\" World writable directories without the sticky bit on the system.\\n   - The following is a list of World writable directories without the sticky bit:\\n$(printf '%s\\n' \"${a_dir[@]}\")\\n   - end of list\\n\"
       fi
       unset a_path; unset a_arr; unset a_file; unset a_dir # Remove arrays
       # If l_output2 is empty, we pass
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n   PASS \\n - * Correctly configured * :\\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :\\n$l_output2\"
          [ -n \"$l_output\" ] && echo -e \"- * Correctly configured * :\\n$l_output\\n\"
       fi
    }
    ```

    Note: On systems with a large number of files and/or directories, this audit may be a long running process
  "
  desc  'fix', "
    - World Writable Files:
      - It is recommended that write access is removed from `other` with the command ( `chmod o-w ` ), but always consult relevant vendor documentation to avoid breaking any application dependencies on a given file.
    - World Writable Directories:
      - Set the sticky bit on all world writable directories with the command ( `chmod a+t ` )

    Run the following script to:
    - Remove other write permission from any world writable files
    - Add the sticky bit to all world writable directories

    ```
    #!/usr/bin/env bash

    {
       l_smask='01000'
       a_file=(); a_dir=() # Initialize arrays
       a_path=(! -path \"/run/user/*\" -a ! -path \"/proc/*\" -a ! -path \"*/containerd/*\" -a ! -path \"*/kubelet/pods/*\" -a ! -path \"*/kubelet/plugins/*\" -a ! -path \"/sys/*\" -a ! -path \"/snap/*\")
       while IFS= read -r l_mount; do
          while IFS= read -r -d $'\\0' l_file; do
             if [ -e \"$l_file\" ]; then
                l_mode=\"$(stat -Lc '%#a' \"$l_file\")\"
                if [ -f \"$l_file\" ]; then # Remove excess permissions from WW files
                   echo -e \" - File: \\\"$l_file\\\" is mode: \\\"$l_mode\\\"\\n  - removing write permission on \\\"$l_file\\\" from \\\"other\\\"\"
                   chmod o-w \"$l_file\"
                fi
                if [ -d \"$l_file\" ]; then # Add sticky bit
                   if [ ! $(( $l_mode & $l_smask )) -gt 0 ]; then
                      echo -e \" - Directory: \\\"$l_file\\\" is mode: \\\"$l_mode\\\" and doesn't have the sticky bit set\\n  - Adding the sticky bit\"
                      chmod a+t \"$l_file\"
                   fi
                fi
             fi
          done < <(find \"$l_mount\" -xdev \\( \"${a_path[@]}\" \\) \\( -type f -o -type d \\) -perm -0002 -print0 2> /dev/null)
       done < <(findmnt -Dkerno fstype,target | awk '($1 !~ /^\\s*(nfs|proc|smb|vfat|iso9660|efivarfs|selinuxfs)/ && $2 !~ /^(\\/run\\/user\\/|\\/tmp|\\/var\\/tmp)/){print $2}') 
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.11'
  tag cis_number:            '7.1.11'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070111r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure world writable files and directories are secured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070111r1_rule.'
  end
end
