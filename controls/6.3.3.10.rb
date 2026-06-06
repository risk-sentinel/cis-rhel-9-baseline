# encoding: UTF-8

control 'C-6.3.3.10' do
  title 'Ensure successful file system mounts are collected'
  desc  "
    Monitor the use of the `mount` system call. The `mount` (and `umount` ) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user

    It is highly unusual for a non privileged user to `mount` file systems to the system. While tracking `mount` commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exported to the media. System administrators who wish to determine if data were exported, would also have to track successful `open`, `creat` and `truncate` system calls requiring write access to a file under the mount point of the external media file system. This could give a fair indication that a write occurred. The only way to truly prove it, would be to track successful writes to the external media. Tracking write system calls could quickly fill up the audit log and is not recommended. Recommendations on configuration options to track data export to media is beyond the scope of this document.
  "
  desc  'rationale', "
    Monitor the use of the `mount` system call. The `mount` (and `umount` ) system call controls the mounting and unmounting of file systems. The parameters below configure the system to create an audit record when the mount system call is used by a non-privileged user

    It is highly unusual for a non privileged user to `mount` file systems to the system. While tracking `mount` commands gives the system administrator evidence that external media may have been mounted (based on a review of the source of the mount and confirming it's an external media type), it does not conclusively indicate that data was exported to the media. System administrators who wish to determine if data were exported, would also have to track successful `open`, `creat` and `truncate` system calls requiring write access to a file under the mount point of the external media file system. This could give a fair indication that a write occurred. The only way to truly prove it, would be to track successful writes to the external media. Tracking write system calls could quickly fill up the audit log and is not recommended. Recommendations on configuration options to track data export to media is beyond the scope of this document.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&/ -S/ \\
     &&/mount/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=unset -k mounts
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=unset -k mounts
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # {
     UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
     [ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
     &&/ -F *auid>=${UID_MIN}/ \\
     &&/ -S/ \\
     &&/mount/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" \\
     || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts
    -a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor successful file system mounts.

    _Example:_

    ```
    # {
    UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
    [ -n \"${UID_MIN}\" ] && printf \"
    -a always,exit -F arch=b32 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
    -a always,exit -F arch=b64 -S mount -F auid>=$UID_MIN -F auid!=unset -k mounts
    \" >> /etc/audit/rules.d/50-mounts.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Load audit rules

    Merge and load the rules into active configuration:

    ```
    # augenrules --load
    ```

    Check if reboot is required.

    ```
    # if [[ $(auditctl -s | grep \"enabled\") =~ \"2\" ]]; then printf \"Reboot required to load rules\\n\"; fi
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_rid:               '6.3.3.10'
  tag cis_number:            '6.3.3.10'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030310r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +mounts|key=mounts)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end