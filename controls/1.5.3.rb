# encoding: UTF-8

control 'C-1.5.3' do
  title 'Ensure core dump backtraces are disabled'
  desc  "
    A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file.

    A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems, increasing the risk to the system.
  "
  desc  'rationale', "
    A core dump is the memory of an executable program. It is generally used to determine why a program aborted. It can also be used to glean confidential information from a core file.

    A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems, increasing the risk to the system.
  "
  desc  'check', "
    Run the following script to verify `ProcessSizeMax` is set to `0` in `/etc/systemd/coredump.conf` or a file in the `/etc/systemd/coredump.conf.d/` directory:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       a_parlist=(\"ProcessSizeMax=0\")
       l_systemd_config_file=\"/etc/systemd/coredump.conf\" # Main systemd configuration file
       config_file_parameter_chk()
       {
          unset A_out; declare -A A_out # Check config file(s) setting
          while read -r l_out; do
             if [ -n \"$l_out\" ]; then
                if [[ $l_out =~ ^\\s*# ]]; then
                   l_file=\"${l_out//# /}\"
                else
                   l_systemd_parameter=\"$(awk -F= '{print $1}' <<< \"$l_out\" | xargs)\"
                   grep -Piq -- \"^\\h*$l_systemd_parameter_name\\b\" <<< \"$l_systemd_parameter\" && A_out+=([\"$l_systemd_parameter\"]=\"$l_file\")
                fi
             fi
          done < <(/usr/bin/systemd-analyze cat-config \"$l_systemd_config_file\" | grep -Pio '^\\h*([^#\\n\\r]+|#\\h*\\/[^#\\n\\r\\h]+\\.conf\\b)')
          if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
             while IFS=\"=\" read -r l_systemd_file_parameter_name l_systemd_file_parameter_value; do
                l_systemd_file_parameter_name=\"${l_systemd_file_parameter_name// /}\"
                l_systemd_file_parameter_value=\"${l_systemd_file_parameter_value// /}\"
                if grep -Piq \"^\\h*$l_systemd_parameter_value\\b\" <<< \"$l_systemd_file_parameter_value\"; then
                   l_output=\"$l_output\\n - \\\"$l_systemd_parameter_name\\\" is correctly set to \\\"$l_systemd_file_parameter_value\\\" in \\\"$(printf '%s' \"${A_out[@]}\")\\\"\\n\"
                else
                   l_output2=\"$l_output2\\n - \\\"$l_systemd_parameter_name\\\" is incorrectly set to \\\"$l_systemd_file_parameter_value\\\" in \\\"$(printf '%s' \"${A_out[@]}\")\\\" and should have a value matching: \\\"$l_systemd_parameter_value\\\"\\n\"
                fi
             done < <(grep -Pio -- \"^\\h*$l_systemd_parameter_name\\h*=\\h*\\H+\" \"${A_out[@]}\")
          else
             l_output2=\"$l_output2\\n - \\\"$l_systemd_parameter_name\\\" is not set in an included file\\n    Note: \\\"$l_systemd_parameter_name\\\" May be set in a file that's ignored by load procedure \\n\"
          fi
       }
       while IFS=\"=\" read -r l_systemd_parameter_name l_systemd_parameter_value; do # Assess and check parameters
          l_systemd_parameter_name=\"${l_systemd_parameter_name// /}\"
          l_systemd_parameter_value=\"${l_systemd_parameter_value// /}\"
          config_file_parameter_chk
       done < <(printf '%s\\n' \"${a_parlist[@]}\")
       if [ -z \"$l_output2\" ]; then # Provide output from checks
          echo -e \"\\n- Audit Result:\\n   PASS \\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\"
          [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Create or edit the file `/etc/systemd/coredump.conf`, or a file in the `/etc/systemd/coredump.conf.d` directory ending in `.conf`.

    Edit or add the following line in the `[Coredump]` section:

    ```
    ProcessSizeMax=0
    ```

    _Example:_

    ```
    #!/usr/bin/env bash

    {
       [ ! -d /etc/systemd/coredump.conf.d/ ] && mkdir /etc/systemd/coredump.conf.d/
       if grep -Psq -- '^\\h*\\[Coredump\\]' /etc/systemd/coredump.conf.d/60-coredump.conf; then
          printf '%s\\n' \"ProcessSizeMax=0\" >> /etc/systemd/coredump.conf.d/60-coredump.conf
       else
          printf '%s\\n' \"[Coredump]\" \"ProcessSizeMax=0\" >> /etc/systemd/coredump.conf.d/60-coredump.conf
       fi
    }
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '1.5.3'
  tag cis_number:            '1.5.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010503r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhP -- '^\h*ProcessSizeMax\h*=\h*0\b' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end