# encoding: UTF-8

control 'C-6.2.4.1' do
  title 'Ensure access to all logfiles has been configured'
  desc  "
    Log files contain information from many services on the the local system, or in the event of a centralized log server, others systems logs as well. 

    In general log files are found in `/var/log/`, although application can be configured to store logs elsewhere. Should your application store logs in another, ensure to run the same test on that location.

    It is important that log files have the correct permissions to ensure that sensitive data is protected and that only the appropriate users / groups have access to them.
  "
  desc  'rationale', "
    Log files contain information from many services on the the local system, or in the event of a centralized log server, others systems logs as well. 

    In general log files are found in `/var/log/`, although application can be configured to store logs elsewhere. Should your application store logs in another, ensure to run the same test on that location.

    It is important that log files have the correct permissions to ensure that sensitive data is protected and that only the appropriate users / groups have access to them.
  "
  desc  'check', "
    Run the following script to verify that files in `/var/log/` have appropriate permissions and ownership:
    - `/var/log/` files: `(lastlog|lastlog.*|wtmp|wtmp.*|wtmp-*|btmp|btmp.*|btmp-*)` user and group ownership is `root` and permissions are set to `0664` or more restrictive.
    - `/var/log` files: `(secure|auth.log|syslog|messages|*.journal|.*journal~| * other files)` user ownership `(root|syslog)`, group ownership `(root|adm)`, and permissions are set to `0640` or more restrictive.
    - `/var/log` files: `(gdm|gdm3|SSSD)` user ownership is `(root|SSSD)`, group ownership is `(root|SSSD|gdm|gdm3)`, and permissions are set to `660` or more restrictive.
    ```
    #!/usr/bin/env bash

    {
       l_op2=\"\" l_output2=\"\"
       l_uidmin=\"$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)\"
       file_test_chk()
       {
          l_op2=\"\"
          if [ $(( $l_mode & $perm_mask )) -gt 0 ]; then
             l_op2=\"$l_op2\\n  - Mode: \\\"$l_mode\\\" should be \\\"$maxperm\\\" or more restrictive\"
          fi
          if [[ ! \"$l_user\" =~ $l_auser ]]; then
             l_op2=\"$l_op2\\n  - Owned by: \\\"$l_user\\\" and should be owned by \\\"${l_auser//|/ or }\\\"\"
          fi
          if [[ ! \"$l_group\" =~ $l_agroup ]]; then
             l_op2=\"$l_op2\\n  - Group owned by: \\\"$l_group\\\" and should be group owned by \\\"${l_agroup//|/ or }\\\"\"
          fi
          [ -n \"$l_op2\" ] && l_output2=\"$l_output2\\n - File: \\\"$l_fname\\\" is:$l_op2\\n\"
       }
       unset a_file && a_file=() # clear and initialize array
       # Loop to create array with stat of files that could possibly fail one of the audits
       while IFS= read -r -d $'\\0' l_file; do
          [ -e \"$l_file\" ] && a_file+=(\"$(stat -Lc '%n^%#a^%U^%u^%G^%g' \"$l_file\")\")
       done < <(find -L /var/log -type f \\( -perm /0137 -o ! -user root -o ! -group root \\) -print0)
       while IFS=\"^\" read -r l_fname l_mode l_user l_uid l_group l_gid; do
          l_bname=\"$(basename \"$l_fname\")\"
          case \"$l_bname\" in
             lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README)
                perm_mask='0113'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_auser=\"root\"
                l_agroup=\"(root|utmp)\"
                file_test_chk
                ;;
             secure | auth.log | syslog | messages)
                perm_mask='0137'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_auser=\"(root|syslog)\"
                l_agroup=\"(root|adm)\"
                file_test_chk
                ;;
             SSSD | sssd)
                perm_mask='0117'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_auser=\"(root|SSSD)\"
                l_agroup=\"(root|SSSD)\"
                file_test_chk            
                ;;
             gdm | gdm3)
                perm_mask='0117'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_auser=\"root\"
                l_agroup=\"(root|gdm|gdm3)\"
                file_test_chk   
                ;;
             *.journal | *.journal~)
                perm_mask='0137'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_auser=\"root\"
                l_agroup=\"(root|systemd-journal)\"
                file_test_chk
                ;;
             *)
                perm_mask='0137'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_auser=\"(root|syslog)\"
                l_agroup=\"(root|adm)\"
                if [ \"$l_uid\" -lt \"$l_uidmin\" ] && [ -z \"$(awk -v grp=\"$l_group\" -F: '$1==grp {print $4}' /etc/group)\" ]; then
                   if [[ ! \"$l_user\" =~ $l_auser ]]; then
                      l_auser=\"(root|syslog|$l_user)\"
                   fi
                   if [[ ! \"$l_group\" =~ $l_agroup ]]; then
                      l_tst=\"\"
                      while l_out3=\"\" read -r l_duid; do
                         [ \"$l_duid\" -ge \"$l_uidmin\" ] && l_tst=failed
                      done <<< \"$(awk -F: '$4=='\"$l_gid\"' {print $3}' /etc/passwd)\"
                      [ \"$l_tst\" != \"failed\" ] && l_agroup=\"(root|adm|$l_group)\"
                   fi
                fi
                file_test_chk
                ;;
          esac
       done <<< \"$(printf '%s\\n' \"${a_file[@]}\")\"
       unset a_file # Clear array
       # If all files passed, then we pass
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Results:\\n  Pass \\n- All files in \\\"/var/log/\\\" have appropriate permissions and ownership\\n\"
       else
          # print the reason why we are failing
          echo -e \"\\n- Audit Results:\\n  Fail \\n$l_output2\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to update permissions and ownership on files in `/var/log`. 

    Although the script is not destructive, ensure that the output is captured in the event that the remediation causes issues.

    ```
    #!/usr/bin/env bash

    {
       l_op2=\"\" l_output2=\"\"
       l_uidmin=\"$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)\"
       file_test_fix()
       {
          l_op2=\"\"
          l_fuser=\"root\"
          l_fgroup=\"root\"
          if [ $(( $l_mode & $perm_mask )) -gt 0 ]; then
             l_op2=\"$l_op2\\n  - Mode: \\\"$l_mode\\\" should be \\\"$maxperm\\\" or more restrictive\\n   - Removing excess permissions\"
             chmod \"$l_rperms\" \"$l_fname\"
          fi
          if [[ ! \"$l_user\" =~ $l_auser ]]; then
             l_op2=\"$l_op2\\n  - Owned by: \\\"$l_user\\\" and should be owned by \\\"${l_auser//|/ or }\\\"\\n   - Changing ownership to: \\\"$l_fuser\\\"\"
             chown \"$l_fuser\" \"$l_fname\"
          fi
          if [[ ! \"$l_group\" =~ $l_agroup ]]; then
             l_op2=\"$l_op2\\n  - Group owned by: \\\"$l_group\\\" and should be group owned by \\\"${l_agroup//|/ or }\\\"\\n   - Changing group ownership to: \\\"$l_fgroup\\\"\"
             chgrp \"$l_fgroup\" \"$l_fname\"
          fi
          [ -n \"$l_op2\" ] && l_output2=\"$l_output2\\n - File: \\\"$l_fname\\\" is:$l_op2\\n\"
       }
       unset a_file && a_file=() # clear and initialize array
       # Loop to create array with stat of files that could possibly fail one of the audits
       while IFS= read -r -d $'\\0' l_file; do
          [ -e \"$l_file\" ] && a_file+=(\"$(stat -Lc '%n^%#a^%U^%u^%G^%g' \"$l_file\")\")
       done < <(find -L /var/log -type f \\( -perm /0137 -o ! -user root -o ! -group root \\) -print0)
       while IFS=\"^\" read -r l_fname l_mode l_user l_uid l_group l_gid; do
          l_bname=\"$(basename \"$l_fname\")\"
          case \"$l_bname\" in
             lastlog | lastlog.* | wtmp | wtmp.* | wtmp-* | btmp | btmp.* | btmp-* | README)
                perm_mask='0113'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_rperms=\"ug-x,o-wx\"
                l_auser=\"root\"
                l_agroup=\"(root|utmp)\"
                file_test_fix
                ;;
             secure | auth.log | syslog | messages)
                perm_mask='0137'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_rperms=\"u-x,g-wx,o-rwx\"
                l_auser=\"(root|syslog)\"
                l_agroup=\"(root|adm)\"
                file_test_fix
                ;;
             SSSD | sssd)
                perm_mask='0117'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_rperms=\"ug-x,o-rwx\"
                l_auser=\"(root|SSSD)\"
                l_agroup=\"(root|SSSD)\"
                file_test_fix            
                ;;
             gdm | gdm3)
                perm_mask='0117'
                l_rperms=\"ug-x,o-rwx\"
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_auser=\"root\"
                l_agroup=\"(root|gdm|gdm3)\"
                file_test_fix   
                ;;
             *.journal | *.journal~)
                perm_mask='0137'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_rperms=\"u-x,g-wx,o-rwx\"
                l_auser=\"root\"
                l_agroup=\"(root|systemd-journal)\"       
                file_test_fix
                ;;
             *)
                perm_mask='0137'
                maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
                l_rperms=\"u-x,g-wx,o-rwx\"
                l_auser=\"(root|syslog)\"
                l_agroup=\"(root|adm)\"
                if [ \"$l_uid\" -lt \"$l_uidmin\" ] && [ -z \"$(awk -v grp=\"$l_group\" -F: '$1==grp {print $4}' /etc/group)\" ]; then
                   if [[ ! \"$l_user\" =~ $l_auser ]]; then
                      l_auser=\"(root|syslog|$l_user)\"
                   fi
                   if [[ ! \"$l_group\" =~ $l_agroup ]]; then
                      l_tst=\"\"
                      while l_out3=\"\" read -r l_duid; do
                         [ \"$l_duid\" -ge \"$l_uidmin\" ] && l_tst=failed
                      done <<< \"$(awk -F: '$4=='\"$l_gid\"' {print $3}' /etc/passwd)\"
                      [ \"$l_tst\" != \"failed\" ] && l_agroup=\"(root|adm|$l_group)\"
                   fi
                fi
                file_test_fix
                ;;
          esac
       done <<< \"$(printf '%s\\n' \"${a_file[@]}\")\"
       unset a_file # Clear array
       # If all files passed, then we report no changes
       if [ -z \"$l_output2\" ]; then
          echo -e \"- All files in \\\"/var/log/\\\" have appropriate permissions and ownership\\n  - No changes required\\n\"
       else
          # print report of changes
          echo -e \"\\n$l_output2\"
       fi
    }
    ```

    Note: You may also need to change the configuration for your logging software or services for any logs that had incorrect permissions.

    If there are services that log to other locations, ensure that those log files have the appropriate access configured.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '6.2.4.1'
  tag cis_number:            '6.2.4.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020401r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{find /var/log -type f -perm /0137 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end