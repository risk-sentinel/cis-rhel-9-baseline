# encoding: UTF-8

control 'C-5.1.2' do
  title 'Ensure permissions on SSH private host key files are configured'
  desc  "
    An SSH private key is one of two files used in SSH public key authentication.  In this authentication method, the possession of the private key is proof of identity. Only a private key that corresponds to a public key will be able to authenticate successfully. The private keys need to be stored and handled carefully, and no copies of the private key should be distributed.

    If an unauthorized user obtains the private SSH host key file, the host could be impersonated
  "
  desc  'rationale', "
    An SSH private key is one of two files used in SSH public key authentication.  In this authentication method, the possession of the private key is proof of identity. Only a private key that corresponds to a public key will be able to authenticate successfully. The private keys need to be stored and handled carefully, and no copies of the private key should be distributed.

    If an unauthorized user obtains the private SSH host key file, the host could be impersonated
  "
  desc  'check', "
    Run the following script to verify SSH private host key files are owned by the root user and either:

    - owned by the group root and mode `0600` or more restrictive

    - OR -

    - owned by the group designated to own openSSH private keys and mode `0640` or more restrictive

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       l_ssh_group_name=\"$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)\"
       f_file_chk()
       {
          while IFS=: read -r l_file_mode l_file_owner l_file_group; do
             l_out2=\"\"
             [ \"$l_file_group\" = \"$l_ssh_group_name\" ] && l_pmask=\"0137\" || l_pmask=\"0177\"
             l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_pmask )) )\"
             if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then
                l_out2=\"$l_out2\\n  - Mode: \\\"$l_file_mode\\\" should be mode: \\\"$l_maxperm\\\" or more restrictive\"
             fi
             if [ \"$l_file_owner\" != \"root\" ]; then
                l_out2=\"$l_out2\\n  - Owned by: \\\"$l_file_owner\\\" should be owned by \\\"root\\\"\"
             fi
             if [[ ! \"$l_file_group\" =~ ($l_ssh_group_name|root) ]]; then
                l_out2=\"$l_out2\\n  - Owned by group \\\"$l_file_group\\\" should be group owned by: \\\"$l_ssh_group_name\\\" or \\\"root\\\"\"
             fi
             if [ -n \"$l_out2\" ]; then
                l_output2=\"$l_output2\\n - File: \\\"$l_file\\\"$l_out2\"
             else
                l_output=\"$l_output\\n - File: \\\"$l_file\\\"\\n  - Correct: mode: \\\"$l_file_mode\\\", owner: \\\"$l_file_owner\\\", and group owner: \\\"$l_file_group\\\" configured\"
             fi
          done < <(stat -Lc '%#a:%U:%G' \"$l_file\")
       }
       while IFS= read -r -d $'\\0' l_file; do 
          if ssh-keygen -lf &>/dev/null \"$l_file\"; then 
             file \"$l_file\" | grep -Piq -- '\\bopenssh\\h+([^#\\n\\r]+\\h+)?private\\h+key\\b' && f_file_chk
          fi
       done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)
       if [ -z \"$l_output2\" ]; then
          [ -z \"$l_output\" ] && l_output=\"\\n  - No openSSH private keys found\"
          echo -e \"\\n- Audit Result:\\n   PASS \\n - * Correctly configured * :$l_output\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n - * Correctly configured * :\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to set mode, ownership, and group on the private SSH host key files:

    ```
    {
       l_output=\"\" l_output2=\"\"
       l_ssh_group_name=\"$(awk -F: '($1 ~ /^(ssh_keys|_?ssh)$/) {print $1}' /etc/group)\"
       f_file_access_fix()
       {
          while IFS=: read -r l_file_mode l_file_owner l_file_group; do
             echo \"File: \\\"$l_file\\\" mode: \\\"$l_file_mode\\\" owner \\\"$l_file_owner\\\" group \\\"$l_file_group\\\"\"
             l_out2=\"\"
             [ \"$l_file_group\" = \"$l_ssh_group_name\" ] && l_pmask=\"0137\" || l_pmask=\"0177\"
             l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_pmask )) )\"
             if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then
                l_out2=\"$l_out2\\n  - Mode: \\\"$l_file_mode\\\" should be mode: \\\"$l_maxperm\\\" or more restrictive\\n   - updating to mode: \\:$l_maxperm\\\"\"
                if [ \"l_file_group\" = \"$l_ssh_group_name\" ]; then
                   chmod u-x,g-wx,o-rwx \"$l_file\"
                else
                   chmod u-x,go-rwx \"$l_file\"
                fi
             fi
             if [ \"$l_file_owner\" != \"root\" ]; then
                l_out2=\"$l_out2\\n  - Owned by: \\\"$l_file_owner\\\" should be owned by \\\"root\\\"\\n   - Changing ownership to \\\"root\\\"\"
                chown root \"$l_file\"
             fi
             if [[ ! \"$l_file_group\" =~ ($l_ssh_group_name|root) ]]; then
                [ -n \"$l_ssh_group_name\" ] && l_new_group=\"$l_ssh_group_name\" || l_new_group=\"root\"
                l_out2=\"$l_out2\\n  - Owned by group \\\"$l_file_group\\\" should be group owned by: \\\"$l_ssh_group_name\\\" or \\\"root\\\"\\n   - Changing group ownership to \\\"$l_new_group\\\"\"
                chgrp \"$l_new_group\" \"$l_file\"
             fi
             if [ -n \"$l_out2\" ]; then
                l_output2=\"$l_output2\\n - File: \\\"$l_file\\\"$l_out2\"
             else
                l_output=\"$l_output\\n - File: \\\"$l_file\\\"\\n  - Correct: mode: \\\"$l_file_mode\\\", owner: \\\"$l_file_owner\\\", and group owner: \\\"$l_file_group\\\" configured\"
             fi
          done < <(stat -Lc '%#a:%U:%G' \"$l_file\")
       }
       while IFS= read -r -d $'\\0' l_file; do 
          if ssh-keygen -lf &>/dev/null \"$l_file\"; then 
             file \"$l_file\" | grep -Piq -- '\\bopenssh\\h+([^#\\n\\r]+\\h+)?private\\h+key\\b' && f_file_access_fix
          fi
       done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- No access changes required\\n\"
       else
          echo -e \"\\n- Remediation results:\\n$l_output2\\n\"
       fi
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.1.2'
  tag cis_number:            '5.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command("find /etc/ssh -xdev -name 'ssh_host_*_key' -type f -perm /077") do
    its('stdout') { should be_empty }
  end
end