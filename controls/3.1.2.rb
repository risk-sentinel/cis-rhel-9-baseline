# encoding: UTF-8

control 'C-3.1.2' do
  title 'Ensure wireless interfaces are disabled'
  desc  "
    Wireless networking is used when wired networks are unavailable.

    - IF - wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface.
  "
  desc  'rationale', "
    Wireless networking is used when wired networks are unavailable.

    - IF - wireless is not to be used, wireless devices can be disabled to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following script to verify no wireless interfaces are active on the system:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       module_chk()
       {
          # Check how module will be loaded
          l_loadable=\"$(modprobe -n -v \"$l_mname\")\"
          if grep -Pq -- '^\\h*install \\/bin\\/(true|false)' <<< \"$l_loadable\"; then
             l_output=\"$l_output\\n - module: \\\"$l_mname\\\" is not loadable: \\\"$l_loadable\\\"\"
          else
             l_output2=\"$l_output2\\n - module: \\\"$l_mname\\\" is loadable: \\\"$l_loadable\\\"\"
          fi
          # Check is the module currently loaded
          if ! lsmod | grep \"$l_mname\" > /dev/null 2>&1; then
             l_output=\"$l_output\\n - module: \\\"$l_mname\\\" is not loaded\"
          else
             l_output2=\"$l_output2\\n - module: \\\"$l_mname\\\" is loaded\"
          fi
          # Check if the module is deny listed
          if modprobe --showconfig | grep -Pq -- \"^\\h*blacklist\\h+$l_mname\\b\"; then
             l_output=\"$l_output\\n - module: \\\"$l_mname\\\" is deny listed in: \\\"$(grep -Pl -- \"^\\h*blacklist\\h+$l_mname\\b\" /etc/modprobe.d/*)\\\"\"
          else
             l_output2=\"$l_output2\\n - module: \\\"$l_mname\\\" is not deny listed\"
          fi
       }
       if [ -n \"$(find /sys/class/net/*/ -type d -name wireless)\" ]; then
          l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename \"$(readlink -f \"$driverdir\"/device/driver/module)\";done | sort -u)
          for l_mname in $l_dname; do
             module_chk
          done
       fi
       # Report results. If no failures output in l_output2, we pass
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n   PASS \"
          if [ -z \"$l_output\" ]; then
             echo -e \"\\n - System has no wireless NICs installed\"
          else
             echo -e \"\\n$l_output\\n\"
          fi
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to disable any wireless interfaces:

    ```
    #!/usr/bin/env bash

    {
       module_fix()
       {
          if ! modprobe -n -v \"$l_mname\" | grep -P -- '^\\h*install \\/bin\\/(true|false)'; then
             echo -e \" - setting module: \\\"$l_mname\\\" to be un-loadable\"
             echo -e \"install $l_mname /bin/false\" >> /etc/modprobe.d/\"$l_mname\".conf
          fi
          if lsmod | grep \"$l_mname\" > /dev/null 2>&1; then
             echo -e \" - unloading module \\\"$l_mname\\\"\"
             modprobe -r \"$l_mname\"
          fi
          if ! grep -Pq -- \"^\\h*blacklist\\h+$l_mname\\b\" /etc/modprobe.d/*; then
             echo -e \" - deny listing \\\"$l_mname\\\"\"
             echo -e \"blacklist $l_mname\" >> /etc/modprobe.d/\"$l_mname\".conf
          fi
       }
       if [ -n \"$(find /sys/class/net/*/ -type d -name wireless)\" ]; then
          l_dname=$(for driverdir in $(find /sys/class/net/*/ -type d -name wireless | xargs -0 dirname); do basename \"$(readlink -f \"$driverdir\"/device/driver/module)\";done | sort -u)
          for l_mname in $l_dname; do
             module_fix
          done
       fi
    }
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'AC-20 (1) (a)', 'AC-20 (1) (b)']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-CNA-MAT', 'KSI-IAM-ELP', 'KSI-IAM-JIT', 'KSI-MLA-LET', 'KSI-MLA-OSM']
  tag nist_r4:               ['AC-20 (1) (a)', 'AC-20 (1) (b)', 'CM-7 a']
  tag cci:                   ['CCI-000381', 'CCI-002336', 'CCI-002337']
  tag cis_rid:               '3.1.2'
  tag cis_number:            '3.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-030102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{find /sys/class/net/*/ -maxdepth 1 -name wireless 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end