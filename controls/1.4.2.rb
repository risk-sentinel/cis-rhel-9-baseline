# encoding: UTF-8

control 'C-1.4.2' do
  title 'Ensure access to bootloader config is configured'
  desc  "
    The grub files contain information on boot settings and passwords for unlocking boot options.

    Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them.
  "
  desc  'rationale', "
    The grub files contain information on boot settings and passwords for unlocking boot options.

    Setting the permissions to read and write for root only prevents non-root users from seeing the boot parameters or changing them. Non-root users who read the boot parameters may be able to identify weaknesses in security upon boot and be able to exploit them.
  "
  desc  'check', "
    Run the following script to verify grub configuration files:
    - For systems using UEFI (Files located in `/boot/efi/EFI/*`):
      - Mode is `0700` or more restrictive
    - For systems using BIOS (Files located in `/boot/grub2/*`):
      - Mode is `0600` or more restrictive
    - Owner is the user `root`
    - Group owner is group `root`

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"  
       file_mug_chk()
       {
          l_out=\"\" l_out2=\"\"
          [[ \"$(dirname \"$l_file\")\" =~ ^\\/boot\\/efi\\/EFI ]] && l_pmask=\"0077\" || l_pmask=\"0177\"
          l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_pmask )) )\"
          if [ $(( $l_mode & $l_pmask )) -gt 0 ]; then
             l_out2=\"$l_out2\\n   - Is mode \\\"$l_mode\\\" and should be mode: \\\"$l_maxperm\\\" or more restrictive\"
          else
             l_out=\"$l_out\\n   - Is correctly mode: \\\"$l_mode\\\" which is mode: \\\"$l_maxperm\\\" or more restrictive\"
          fi
          if [ \"$l_user\" = \"root\" ]; then
             l_out=\"$l_out\\n   - Is correctly owned by user: \\\"$l_user\\\"\"
          else
             l_out2=\"$l_out2\\n   - Is owned by user: \\\"$l_user\\\" and should be owned by user: \\\"root\\\"\"
          fi
          if [ \"$l_group\" = \"root\" ]; then
             l_out=\"$l_out\\n   - Is correctly group-owned by group: \\\"$l_user\\\"\"
          else
             l_out2=\"$l_out2\\n   - Is group-owned by group: \\\"$l_user\\\" and should be group-owned by group: \\\"root\\\"\"
          fi
          [ -n \"$l_out\" ] && l_output=\"$l_output\\n  - File: \\\"$l_file\\\"$l_out\\n\"
          [ -n \"$l_out2\" ] && l_output2=\"$l_output2\\n  - File: \\\"$l_file\\\"$l_out2\\n\"
       }
       while IFS= read -r -d $'\\0' l_gfile; do
          while read -r l_file l_mode l_user l_group; do
             file_mug_chk
          done <<< \"$(stat -Lc '%n %#a %U %G' \"$l_gfile\")\"
       done < <(find /boot -type f \\( -name 'grub*' -o -name 'user.cfg' \\) -print0)
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n  * PASS *\\n- * Correctly set * :\\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \" - * Correctly set * :\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following to update the mode, ownership, and group ownership of the grub configuration files:

    - IF - the system uses UEFI (Files located in `/boot/efi/EFI/*`)

    Edit `/etc/fstab` and add the `fmask=0077`, `uid=0`, and `gid=0` options:

    _Example:_

    ``` /boot/efi vfat defaults,umask=0027,fmask=0077,uid=0,gid=0 0 0
    ```

    Note: This may require a re-boot to enable the change

     - OR - 

    - IF - the system uses BIOS (Files located in `/boot/grub2/*`)

    Run the following commands to set ownership and permissions on your grub configuration file(s):

    ```
    # [ -f /boot/grub2/grub.cfg ] && chown root:root /boot/grub2/grub.cfg
    # [ -f /boot/grub2/grub.cfg ] && chmod u-x,go-rwx /boot/grub2/grub.cfg

    # [ -f /boot/grub2/grubenv ] && chown root:root /boot/grub2/grubenv
    # [ -f /boot/grub2/grubenv ] && chmod u-x,go-rwx /boot/grub2/grubenv

    # [ -f /boot/grub2/user.cfg ] && chown root:root /boot/grub2/user.cfg
    # [ -f /boot/grub2/user.cfg ] && chmod u-x,go-rwx /boot/grub2/user.cfg
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.4.2'
  tag cis_number:            '1.4.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010402r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/boot/grub2/grub.cfg') do
    it { should exist }
    it { should_not be_more_permissive_than('0600') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end