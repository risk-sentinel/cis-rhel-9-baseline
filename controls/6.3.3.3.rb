# encoding: UTF-8

control 'C-6.3.3.3' do
  title 'Ensure events that modify the sudo log file are collected'
  desc  "
    Monitor the `sudo` log file. If the system has been properly configured to disable the use of the `su` command and force all administrators to have to log in first and then use `sudo` to execute privileged commands, then all administrator commands will be logged to `/var/log/sudo.log` . Any time a command is executed, an audit event will be triggered as the `/var/log/sudo.log` file will be opened for write and the executed administration command will be written to the log.

    Changes in `/var/log/sudo.log` indicate that an administrator has executed a command or the log file itself has been tampered with. Administrators will want to correlate the events written to the audit trail with the records written to `/var/log/sudo.log` to verify if unauthorized commands have been executed.
  "
  desc  'rationale', "
    Monitor the `sudo` log file. If the system has been properly configured to disable the use of the `su` command and force all administrators to have to log in first and then use `sudo` to execute privileged commands, then all administrator commands will be logged to `/var/log/sudo.log` . Any time a command is executed, an audit event will be triggered as the `/var/log/sudo.log` file will be opened for write and the executed administration command will be written to the log.

    Changes in `/var/log/sudo.log` indicate that an administrator has executed a command or the log file itself has been tampered with. Administrators will want to correlate the events written to the audit trail with the records written to `/var/log/sudo.log` to verify if unauthorized commands have been executed.
  "
  desc  'check', "
    Note: This recommendation requires that the sudo logfile is configured.  See guidance provided in the recommendation \"Ensure sudo log file exists\"

    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # {
     SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/\"//g' -e 's|/|\\\\/|g')
     [ -n \"${SUDO_LOG_FILE}\" ] && awk \"/^ *-w/ \\
     &&/\"${SUDO_LOG_FILE}\"/ \\
     &&/ +-p *wa/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules \\
     || printf \"ERROR: Variable 'SUDO_LOG_FILE' is unset.\\n\"
    }
    ```

    Verify output of matches:

    ```
    -w /var/log/sudo.log -p wa -k sudo_log_file
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # {
     SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/\"//g' -e 's|/|\\\\/|g')
     [ -n \"${SUDO_LOG_FILE}\" ] && auditctl -l | awk \"/^ *-w/ \\
     &&/\"${SUDO_LOG_FILE}\"/ \\
     &&/ +-p *wa/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" \\
     || printf \"ERROR: Variable 'SUDO_LOG_FILE' is unset.\\n\"
    }
    ```

    Verify output matches:

    ```
    -w /var/log/sudo.log -p wa -k sudo_log_file
    ```
  "
  desc  'fix', "
    Note: This recommendation requires that the sudo logfile is configured.  See guidance provided in the recommendation \"Ensure sudo log file exists\"

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor events that modify the sudo log file.

    _Example:_

    ```
    # {
    SUDO_LOG_FILE=$(grep -r logfile /etc/sudoers* | sed -e 's/.*logfile=//;s/,? .*//' -e 's/\"//g')
    [ -n \"${SUDO_LOG_FILE}\" ] && printf \"
    -w ${SUDO_LOG_FILE} -p wa -k sudo_log_file
    \" >> /etc/audit/rules.d/50-sudo.rules || printf \"ERROR: Variable 'SUDO_LOG_FILE' is unset.\\n\"
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
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b', 'AU-3 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-MLA-OSM', 'KSI-SVC-ACM']
  tag nist_r4:               ['AU-3', 'CM-6 b']
  tag cci:                   ['CCI-000366', 'CCI-000130']
  tag cis_rid:               '6.3.3.3'
  tag cis_number:            '6.3.3.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030303r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(sudo_log_file|/var/log/sudo)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end