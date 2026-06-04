# encoding: UTF-8

control 'C-5.1.1' do
  title 'Ensure permissions on /etc/ssh/sshd_config are configured'
  desc  "
    The file `/etc/ssh/sshd_config`, and files ending in `.conf` in the `/etc/ssh/sshd_config.d` directory, contain configuration specifications for `sshd`.

    configuration specifications for `sshd` need to be protected from unauthorized changes by non-privileged users.
  "
  desc  'rationale', "
    The file `/etc/ssh/sshd_config`, and files ending in `.conf` in the `/etc/ssh/sshd_config.d` directory, contain configuration specifications for `sshd`.

    configuration specifications for `sshd` need to be protected from unauthorized changes by non-privileged users.
  "
  desc  'check', "
    Run the following script and verify `/etc/ssh/sshd_config` and files ending in `.conf` in the `/etc/ssh/sshd_config.d` directory are:
     - Mode `0600` or more restrictive
     - Owned by the `root` user
     - Group owned by the group `root`.

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       perm_mask='0177' && maxperm=\"$( printf '%o' $(( 0777 & ~$perm_mask)) )\"
       SSHD_FILES_CHK()
       {
          while IFS=: read -r l_mode l_user l_group; do
             l_out2=\"\"
             [ $(( $l_mode & $perm_mask )) -gt 0 ] && l_out2=\"$l_out2\\n  - Is mode: \\\"$l_mode\\\" should be: \\\"$maxperm\\\" or more restrictive\"
             [ \"$l_user\" != \"root\" ] && l_out2=\"$l_out2\\n  - Is owned by \\\"$l_user\\\" should be owned by \\\"root\\\"\"
             [ \"$l_group\" != \"root\" ] && l_out2=\"$l_out2\\n  - Is group owned by \\\"$l_user\\\" should be group owned by \\\"root\\\"\"
             if [ -n \"$l_out2\" ]; then
                l_output2=\"$l_output2\\n - File: \\\"$l_file\\\":$l_out2\"
             else
                l_output=\"$l_output\\n - File: \\\"$l_file\\\":\\n  - Correct: mode ($l_mode), owner ($l_user), and group owner ($l_group) configured\"
             fi
          done < <(stat -Lc '%#a:%U:%G' \"$l_file\")
       }
       [ -e \"/etc/ssh/sshd_config\" ] && l_file=\"/etc/ssh/sshd_config\" && SSHD_FILES_CHK
       while IFS= read -r -d $'\\0' l_file; do
          [ -e \"$l_file\" ] && SSHD_FILES_CHK
       done < <(find -L /etc/ssh/sshd_config.d -type f  \\( -perm /077 -o ! -user root -o ! -group root \\) -print0 2>/dev/null)
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n  * PASS *\\n- * Correctly set * :\\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \" - * Correctly set * :\\n$l_output\\n\"
       fi
    }
    ```

    - IF - other locations are listed in an `Include` statement, `*.conf` files in these locations should also be checked.
  "
  desc  'fix', "
    Run the following script to set ownership and permissions on `/etc/ssh/sshd_config` and files ending in `.conf` in the `/etc/ssh/sshd_config.d` directory:

    ```
    #!/usr/bin/env bash

    {
       chmod u-x,og-rwx /etc/ssh/sshd_config
       chown root:root /etc/ssh/sshd_config
       while IFS= read -r -d $'\\0' l_file; do
          if [ -e \"$l_file\" ]; then
             chmod u-x,og-rwx \"$l_file\"
             chown root:root \"$l_file\"
          fi
       done < <(find /etc/ssh/sshd_config.d -type f -print0 2>/dev/null)
    }
    ```

    - IF - other locations are listed in an `Include` statement, `*.conf` files in these locations access should also be modified.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.1.1'
  tag cis_number:            '5.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/ssh/sshd_config') do
    it { should exist }
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end