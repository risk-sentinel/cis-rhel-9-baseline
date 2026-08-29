# encoding: UTF-8

control 'C-5.4.2.5' do
  title 'Ensure root path integrity'
  desc  "
    The `root` user can execute any command on the system and could be fooled into executing programs unintentionally if the `PATH` is not set correctly.

    Including the current working directory (.) or other writable directory in `root`'s executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as `root` to execute a Trojan horse program.
  "
  desc  'rationale', "
    The `root` user can execute any command on the system and could be fooled into executing programs unintentionally if the `PATH` is not set correctly.

    Including the current working directory (.) or other writable directory in `root`'s executable path makes it likely that an attacker can gain superuser access by forcing an administrator operating as `root` to execute a Trojan horse program.
  "
  desc  'check', "
    Run the following script to verify root's path does not include:
    - Locations that are not directories
    - An empty directory (`::`)
    - A trailing (`:`)
    - Current working directory (`.`)
    - Non `root` owned directories
    - Directories that less restrictive than mode `0755`

    ```
    #!/usr/bin/env bash

    {
       l_output2=\"\"
       l_pmask=\"0022\"
       l_maxperm=\"$( printf '%o' $(( 0777 & ~$l_pmask )) )\"
       l_root_path=\"$(sudo -Hiu root env | grep '^PATH' | cut -d= -f2)\"
       unset a_path_loc && IFS=\":\" read -ra a_path_loc <<< \"$l_root_path\"
       grep -q \"::\" <<< \"$l_root_path\" && l_output2=\"$l_output2\\n - root's path contains a empty directory (::)\"
       grep -Pq \":\\h*$\" <<< \"$l_root_path\" && l_output2=\"$l_output2\\n - root's path contains a trailing (:)\"
       grep -Pq '(\\h+|:)\\.(:|\\h*$)' <<< \"$l_root_path\" && l_output2=\"$l_output2\\n - root's path contains current working directory (.)\"
       while read -r l_path; do
          if [ -d \"$l_path\" ]; then
             while read -r l_fmode l_fown; do
                [ \"$l_fown\" != \"root\" ] && l_output2=\"$l_output2\\n - Directory: \\\"$l_path\\\" is owned by: \\\"$l_fown\\\" should be owned by \\\"root\\\"\"
                [ $(( $l_fmode & $l_pmask )) -gt 0 ] && l_output2=\"$l_output2\\n - Directory: \\\"$l_path\\\" is mode: \\\"$l_fmode\\\" and should be mode: \\\"$l_maxperm\\\" or more restrictive\"
             done <<< \"$(stat -Lc '%#a %U' \"$l_path\")\"
          else
             l_output2=\"$l_output2\\n - \\\"$l_path\\\" is not a directory\"
          fi
       done <<< \"$(printf \"%s\\n\" \"${a_path_loc[@]}\")\"
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n  * PASS *\\n - Root's path is correctly configured\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - * Reasons for audit failure * :\\n$l_output2\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Correct or justify any:
    - Locations that are not directories
    - Empty directories (`::`)
    - Trailing (`:`)
    - Current working directory (`.`)
    - Non `root` owned directories
    - Directories that less restrictive than mode `0755`
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.4.2.5'
  tag cis_number:            '5.4.2.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040205r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  # access_model axis: root's effective PATH only exists in an interactive root
  # session. Under federated_ssm there is no interactive root login (access is via SSM),
  # so this is N/A. interactive keeps the attestation (PATH unreadable to the scanner).
  if access_federated?
    impact 0.0
    describe 'root PATH integrity N/A (access_model=federated_ssm; no interactive root session — access via SSM)' do
      subject { true }
      it { is_expected.to eq true }
    end
  else
    impact 0.5
    describe 'root path integrity (5.4.2.5)' do
      skip 'operational: the effective PATH of the root account is only resolvable in an interactive root session (unavailable to the unprivileged scanner); operator attests no empty/relative/world-writable PATH entries.'
    end
  end
end