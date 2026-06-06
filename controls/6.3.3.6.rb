# encoding: UTF-8

control 'C-6.3.3.6' do
  title 'Ensure use of privileged commands are collected'
  desc  "
    Monitor privileged programs, those that have the `setuid` and/or `setgid` bit set on execution, to determine if unprivileged users are running these commands.

    Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system.
  "
  desc  'rationale', "
    Monitor privileged programs, those that have the `setuid` and/or `setgid` bit set on execution, to determine if unprivileged users are running these commands.

    Execution of privileged commands by non-privileged users could be an indication of someone trying to gain unauthorized access to the system.
  "
  desc  'check', "
    On disk configuration

    Run the following script to check on disk rules:

    ```
    #!/usr/bin/env bash

    {
       for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv \"noexec|nosuid\" | awk '{print $1}'); do
          for PRIVILEGED in $(find \"${PARTITION}\" -xdev -perm /6000 -type f); do
             grep -qr \"${PRIVILEGED}\" /etc/audit/rules.d && printf \"OK: '${PRIVILEGED}' found in auditing rules.\\n\" || printf \"Warning: '${PRIVILEGED}' not found in on disk configuration.\\n\"
          done
       done
    }
    ```

    Verify that all output is `OK`.

    Running configuration

    Run the following script to check loaded rules:

    ```
    #!/usr/bin/env bash

    {
       RUNNING=$(auditctl -l)
       [ -n \"${RUNNING}\" ] && for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv \"noexec|nosuid\" | awk '{print $1}'); do
          for PRIVILEGED in $(find \"${PARTITION}\" -xdev -perm /6000 -type f); do
             printf -- \"${RUNNING}\" | grep -q \"${PRIVILEGED}\" && printf \"OK: '${PRIVILEGED}' found in auditing rules.\\n\" || printf \"Warning: '${PRIVILEGED}' not found in running configuration.\\n\"
          done
       done \\
       || printf \"ERROR: Variable 'RUNNING' is unset.\\n\"
    }
    ```

    Verify that all output is `OK`.

    Special mount points

    If there are any special mount points that are not visible by default from `findmnt` as per the above audit, said file systems would have to be manually audited.
  "
  desc  'fix', "
    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor the use of privileged commands.

    _Example script:_

    ```
    #!/usr/bin/env bash

    {
      UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
      AUDIT_RULE_FILE=\"/etc/audit/rules.d/50-privileged.rules\"
      NEW_DATA=()
      for PARTITION in $(findmnt -n -l -k -it $(awk '/nodev/ { print $2 }' /proc/filesystems | paste -sd,) | grep -Pv \"noexec|nosuid\" | awk '{print $1}'); do
        readarray -t DATA < <(find \"${PARTITION}\" -xdev -perm /6000 -type f | awk -v UID_MIN=${UID_MIN} '{print \"-a always,exit -F path=\" $1 \" -F perm=x -F auid>=\"UID_MIN\" -F auid!=unset -k privileged\" }')
          for ENTRY in \"${DATA[@]}\"; do
            NEW_DATA+=(\"${ENTRY}\")
          done
      done
      readarray &> /dev/null -t OLD_DATA < \"${AUDIT_RULE_FILE}\"
      COMBINED_DATA=( \"${OLD_DATA[@]}\" \"${NEW_DATA[@]}\" )
      printf '%s\\n' \"${COMBINED_DATA[@]}\" | sort -u > \"${AUDIT_RULE_FILE}\"
    }
    ```

    Merge and load the rules into active configuration:

    ```
    # augenrules --load
    ```

    Check if reboot is required.

    ```
    # if [[ $(auditctl -s | grep \"enabled\") =~ \"2\" ]]; then printf \"Reboot required to load rules\\n\"; fi
    ```

    Special mount points

    If there are any special mount points that are not visible by default from just scanning `/`, change the `PARTITION` variable to the appropriate partition and re-run the remediation.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-3 a']
  tag cci:                   ['CCI-000011', 'CCI-000130']
  tag cis_rid:               '6.3.3.6'
  tag cis_number:            '6.3.3.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030306r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +privileged|key=privileged)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end