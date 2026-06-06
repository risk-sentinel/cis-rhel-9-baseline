# encoding: UTF-8

control 'C-5.1.3' do
  title 'Ensure permissions on SSH public host key files are configured'
  desc  "
    An SSH public key is one of two files used in SSH public key authentication. In this authentication method, a public key is a key that can be used for verifying digital signatures generated using a corresponding private key. Only a public key that corresponds to a private key will be able to authenticate successfully.

    If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
  "
  desc  'rationale', "
    An SSH public key is one of two files used in SSH public key authentication. In this authentication method, a public key is a key that can be used for verifying digital signatures generated using a corresponding private key. Only a public key that corresponds to a private key will be able to authenticate successfully.

    If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
  "
  desc  'check', "
    Run the following command and verify Access does not grant write or execute permissions to group or other for all returned files:

    Run the following script to verify SSH public host key files are mode `0644` or more restrictive, owned by the `root` user, and owned by the `root` group:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       l_pmask=\"0133\" && l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_pmask )) )\"
       FILE_CHK()
       {
          while IFS=: read -r l_file_mode l_file_owner l_file_group; do
             l_out2=\"\"
             if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then
                l_out2=\"$l_out2\\n  - Mode: \\\"$l_file_mode\\\" should be mode: \\\"$l_maxperm\\\" or more restrictive\"
             fi
             if [ \"$l_file_owner\" != \"root\" ]; then
                l_out2=\"$l_out2\\n  - Owned by: \\\"$l_file_owner\\\" should be owned by \\\"root\\\"\"
             fi
             if [ \"$l_file_group\" != \"root\" ]; then
                l_out2=\"$l_out2\\n  - Owned by group \\\"$l_file_group\\\" should be group owned by group: \\\"root\\\"\"
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
             file \"$l_file\" | grep -Piq -- '\\bopenssh\\h+([^#\\n\\r]+\\h+)?public\\h+key\\b' && FILE_CHK
          fi
       done < <(find -L /etc/ssh -xdev -type f -print0 2>/dev/null)
       if [ -z \"$l_output2\" ]; then
          [ -z \"$l_output\" ] && l_output=\"\\n  - No openSSH public keys found\"
          echo -e \"\\n- Audit Result:\\n   PASS \\n - * Correctly configured * :$l_output\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n - * Correctly configured * :\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to set mode, ownership, and group on the public SSH host key files:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       l_pmask=\"0133\" && l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_pmask )) )\"
       FILE_ACCESS_FIX()
       {
          while IFS=: read -r l_file_mode l_file_owner l_file_group; do
             l_out2=\"\"
             if [ $(( $l_file_mode & $l_pmask )) -gt 0 ]; then
                l_out2=\"$l_out2\\n  - Mode: \\\"$l_file_mode\\\" should be mode: \\\"$l_maxperm\\\" or more restrictive\\n   - updating to mode: \\:$l_maxperm\\\"\"
                chmod u-x,go-wx
             fi
             if [ \"$l_file_owner\" != \"root\" ]; then
                l_out2=\"$l_out2\\n  - Owned by: \\\"$l_file_owner\\\" should be owned by \\\"root\\\"\\n   - Changing ownership to \\\"root\\\"\"
                chown root \"$l_file\"
             fi
             if [ \"$l_file_group\" != \"root\" ]; then
                l_out2=\"$l_out2\\n  - Owned by group \\\"$l_file_group\\\" should be group owned by: \\\"root\\\"\\n   - Changing group ownership to \\\"root\\\"\"
                chgrp root \"$l_file\"
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
             file \"$l_file\" | grep -Piq -- '\\bopenssh\\h+([^#\\n\\r]+\\h+)?public\\h+key\\b' && FILE_ACCESS_FIX
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
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.1.3'
  tag cis_number:            '5.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command("find /etc/ssh -xdev -name 'ssh_host_*_key.pub' -type f -perm /022") do
    its('stdout') { should be_empty }
  end
end