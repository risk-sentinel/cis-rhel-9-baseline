# encoding: UTF-8

control 'C-3.3.11' do
  title 'Ensure ipv6 router advertisements are not accepted'
  desc  "
    Routers periodically multicast Router Advertisement messages to announce their availability and convey information to neighboring nodes that enable them to be automatically configured on the network.

    `net.ipv6.conf.all.accept_ra` and `net.ipv6.conf.default.accept_ra` determine the systems ability to accept these advertisements

    It is recommended that systems do not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes. Setting `net.ipv6.conf.all.accept_ra` and `net.ipv6.conf.default.accept_ra` to `0` disables the system's ability to accept IPv6 router advertisements.
  "
  desc  'rationale', "
    Routers periodically multicast Router Advertisement messages to announce their availability and convey information to neighboring nodes that enable them to be automatically configured on the network.

    `net.ipv6.conf.all.accept_ra` and `net.ipv6.conf.default.accept_ra` determine the systems ability to accept these advertisements

    It is recommended that systems do not accept router advertisements as they could be tricked into routing traffic to compromised machines. Setting hard routes within the system (usually a single default route to a trusted router) protects the system from bad routes. Setting `net.ipv6.conf.all.accept_ra` and `net.ipv6.conf.default.accept_ra` to `0` disables the system's ability to accept IPv6 router advertisements.
  "
  desc  'check', "
    Run the following script to verify the following kernel parameters are set in the running configuration and correctly loaded from a kernel parameter configuration file:
    - `net.ipv6.conf.all.accept_ra` is set to `0`
    - `net.ipv6.conf.default.accept_ra` is set to `0`

    Note: 
    - kernel parameters are loaded by file and parameter order precedence. The following script observes this precedence as part of the auditing procedure. The parameters being checked may be set correctly in a file. If that file is superseded, the parameter is overridden by an incorrect setting later in that file, or in a canonically later file, that \"correct\" setting will be ignored both by the script and by the system during a normal kernel parameter load sequence.
    - IPv6 kernel parameters only apply to systems where IPv6 is enabled 

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\" l_ipv6_disabled=\"\" # Clear output variables
       a_parlist=(\"net.ipv6.conf.all.accept_ra=0\" \"net.ipv6.conf.default.accept_ra=0\")
       l_ufwscf=\"$([ -f /etc/default/ufw ] && awk -F= '/^\\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)\"
       f_ipv6_chk()
       {
          l_ipv6_disabled=\"\"
          ! grep -Pqs -- '^\\h*0\\b' /sys/module/ipv6/parameters/disable && l_ipv6_disabled=\"yes\"
          if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- \"^\\h*net\\.ipv6\\.conf\\.all\\.disable_ipv6\\h*=\\h*1\\b\" && \\
             sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- \"^\\h*net\\.ipv6\\.conf\\.default\\.disable_ipv6\\h*=\\h*1\\b\"; then
             l_ipv6_disabled=\"yes\"
          fi
          [ -z \"$l_ipv6_disabled\" ] && l_ipv6_disabled=\"no\"
       }
       f_kernel_parameter_chk()
       {
          l_krp=\"$(sysctl \"$l_kpname\" | awk -F= '{print $2}' | xargs)\"
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
                   l_output=\"$l_output\\n - \\\"$l_kpname\\\" is correctly set to \\\"$l_fkpvalue\\\" in \\\"$(printf '%s' \"${A_out[@]}\")\\\"\\n\"
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
          if grep -q '^net.ipv6.' <<< \"$l_kpname\"; then
             [ -z \"$l_ipv6_disabled\" ] && f_ipv6_chk
             if [ \"$l_ipv6_disabled\" = \"yes\" ]; then
                l_output=\"$l_output\\n - IPv6 is disabled on the system, \\\"$l_kpname\\\" is not applicable\"
             else
                f_kernel_parameter_chk
             fi
          else
             f_kernel_parameter_chk
          fi
       done < <(printf '%s\\n' \"${a_parlist[@]}\")
       l_ufwscf=\"$([ -f /etc/default/ufw ] && awk -F= '/^\\s*IPT_SYSCTL=/ {print $2}' /etc/default/ufw)\"
       unset a_parlist; unset A_out # unset arrays
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
    - IF - IPv6 is enabled on the system:

    Set the following parameters in `/etc/sysctl.conf` or a file in `/etc/sysctl.d/` ending in `.conf`:
    - `net.ipv6.conf.all.accept_ra = 0`
    - `net.ipv6.conf.default.accept_ra = 0`

    _Example:_
    ```
    # printf '%s\\n' \"net.ipv6.conf.all.accept_ra = 0\" \"net.ipv6.conf.default.accept_ra = 0\" >> /etc/sysctl.d/60-netipv6_sysctl.conf
    ```

    Run the following script to set the active kernel parameters:

    ```
    #!/usr/bin/env bash

    {
       sysctl -w net.ipv6.conf.all.accept_ra=0
       sysctl -w net.ipv6.conf.default.accept_ra=0
       sysctl -w net.ipv6.route.flush=1
    }
    ```

    Note: If these settings appear in a canonically later file, or later in the same file, these settings will be overwritten
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '3.3.11'
  tag cis_number:            '3.3.11'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-030311r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe kernel_parameter('net.ipv6.conf.all.accept_ra') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv6.conf.default.accept_ra') do
    its('value') { should eq 0 }
  end
end