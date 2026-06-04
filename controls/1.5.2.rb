# encoding: UTF-8

control 'C-1.5.2' do
  title 'Ensure ptrace_scope is restricted'
  desc  "
    The `ptrace()` system call provides a means by which one process (the \"tracer\") may observe and control the execution of another process (the \"tracee\"), and examine and change the tracee's memory and registers.

    If one application is compromised, it would be possible for an attacker to attach to other running processes (e.g. Bash, Firefox, SSH sessions, GPG agent, etc) to extract additional credentials and continue to expand the scope of their attack.

    Enabling restricted mode will limit the ability of a compromised process to PTRACE_ATTACH on other processes running under the same user. With restricted mode, ptrace will continue to work with root user.
  "
  desc  'rationale', "
    The `ptrace()` system call provides a means by which one process (the \"tracer\") may observe and control the execution of another process (the \"tracee\"), and examine and change the tracee's memory and registers.

    If one application is compromised, it would be possible for an attacker to attach to other running processes (e.g. Bash, Firefox, SSH sessions, GPG agent, etc) to extract additional credentials and continue to expand the scope of their attack.

    Enabling restricted mode will limit the ability of a compromised process to PTRACE_ATTACH on other processes running under the same user. With restricted mode, ptrace will continue to work with root user.
  "
  desc  'check', "
    Run the following script to verify the following kernel parameter is set in the running configuration and correctly loaded from a kernel parameter configuration file:
    - `kernel.yama.ptrace_scope` is set to `1`

    Note: kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that \"correct\" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence. 

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       a_parlist=(\"kernel.yama.ptrace_scope=1\")
       l_ufwscf=\"$([ -f /etc/default/ufw ] && awk -F= '/^\\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)\"
       kernel_parameter_chk()
       {  
          l_krp=\"$(sysctl \"$l_kpname\" | awk -F= '{print $2}' | xargs)\" # Check running configuration
          if [ \"$l_krp\" = \"$l_kpvalue\" ]; then
             l_output=\"$l_output\\n - \\\"$l_kpname\\\" is correctly set to \\\"$l_krp\\\" in the running configuration\"
          else
             l_output2=\"$l_output2\\n - \\\"$l_kpname\\\" is incorrectly set to \\\"$l_krp\\\" in the running configuration and should have a value of: \\\"$l_kpvalue\\\"\"
          fi
          unset A_out; declare -A A_out # Check durable setting (files)
          while read -r l_out; do
             if [ -n \"$l_out\" ]; then
                if [[ $l_out =~ ^\\s*# ]]; then
                   l_file=\"${l_out//# /}\"
                else
                   l_kpar=\"$(awk -F= '{print $1}' <<< \"$l_out\" | xargs)\"
                   [ \"$l_kpar\" = \"$l_kpname\" ] && A_out+=([\"$l_kpar\"]=\"$l_file\")
                fi
             fi
          done < <(/usr/lib/systemd/systemd-sysctl --cat-config | grep -Po '^\\h*([^#\\n\\r]+|#\\h*\\/[^#\\n\\r\\h]+\\.conf\\b)')
          if [ -n \"$l_ufwscf\" ]; then # Account for systems with UFW (Not covered by systemd-sysctl --cat-config)
             l_kpar=\"$(grep -Po \"^\\h*$l_kpname\\b\" \"$l_ufwscf\" | xargs)\"
             l_kpar=\"${l_kpar//\\//.}\"
             [ \"$l_kpar\" = \"$l_kpname\" ] && A_out+=([\"$l_kpar\"]=\"$l_ufwscf\")
          fi
          if (( ${#A_out[@]} > 0 )); then # Assess output from files and generate output
             while IFS=\"=\" read -r l_fkpname l_fkpvalue; do
                l_fkpname=\"${l_fkpname// /}\"; l_fkpvalue=\"${l_fkpvalue// /}\"
                if [ \"$l_fkpvalue\" = \"$l_kpvalue\" ]; then
                   l_output=\"$l_output\\n - \\\"$l_kpname\\\" is correctly set to \\\"$l_krp\\\" in \\\"$(printf '%s' \"${A_out[@]}\")\\\"\\n\"
                else
                   l_output2=\"$l_output2\\n - \\\"$l_kpname\\\" is incorrectly set to \\\"$l_fkpvalue\\\" in \\\"$(printf '%s' \"${A_out[@]}\")\\\" and should have a value of: \\\"$l_kpvalue\\\"\\n\"
                fi
             done < <(grep -Po -- \"^\\h*$l_kpname\\h*=\\h*\\H+\" \"${A_out[@]}\")
          else
             l_output2=\"$l_output2\\n - \\\"$l_kpname\\\" is not set in an included file\\n    Note: \\\"$l_kpname\\\" May be set in a file that's ignored by load procedure \\n\"
          fi
       }
       while IFS=\"=\" read -r l_kpname l_kpvalue; do # Assess and check parameters
          l_kpname=\"${l_kpname// /}\"; l_kpvalue=\"${l_kpvalue// /}\"
          if ! grep -Pqs '^\\h*0\\b' /sys/module/ipv6/parameters/disable && grep -q '^net.ipv6.' <<< \"$l_kpname\"; then
             l_output=\"$l_output\\n - IPv6 is disabled on the system, \\\"$l_kpname\\\" is not applicable\"
          else
             kernel_parameter_chk
          fi
       done < <(printf '%s\\n' \"${a_parlist[@]}\")
       if [ -z \"$l_output2\" ]; then # Provide output from checks
          echo -e \"\\n- Audit Result:\\n   PASS \\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Set the following parameter in `/etc/sysctl.conf` or a file in `/etc/sysctl.d/` ending in `.conf`:
    - `kernel.yama.ptrace_scope = 1`

    _Example:_
    ```
    # printf \"
    kernel.yama.ptrace_scope = 1
    \" >> /etc/sysctl.d/60-kernel_sysctl.conf
    ```

    Run the following command to set the active kernel parameter:

    ```
    # sysctl -w kernel.yama.ptrace_scope=1
    ```

    Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.5.2'
  tag cis_number:            '1.5.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010502r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure ptrace_scope is restricted' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-010502r1_rule.'
  end
end
