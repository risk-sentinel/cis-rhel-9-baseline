# encoding: UTF-8

control 'C-1.8.9' do
  title 'Ensure GDM autorun-never is not overridden'
  desc  "
    The autorun-never setting allows the GNOME Desktop Display Manager to disable autorun through GDM.

    By using the lockdown mode in dconf, you can prevent users from changing specific settings.

    To lock down a dconf key or subpath, create a locks subdirectory in the keyfile directory. The files inside this directory contain a list of keys or subpaths to lock. Just as with the keyfiles, you may add any number of files to this directory.

    Example Lock File:
    ```
    # Lock desktop media-handling settings
    /org/gnome/desktop/media-handling/autorun-never
    ```

    Malware on removable media may take advantage of Autorun features when the media is inserted into a system and execute.
  "
  desc  'rationale', "
    The autorun-never setting allows the GNOME Desktop Display Manager to disable autorun through GDM.

    By using the lockdown mode in dconf, you can prevent users from changing specific settings.

    To lock down a dconf key or subpath, create a locks subdirectory in the keyfile directory. The files inside this directory contain a list of keys or subpaths to lock. Just as with the keyfiles, you may add any number of files to this directory.

    Example Lock File:
    ```
    # Lock desktop media-handling settings
    /org/gnome/desktop/media-handling/autorun-never
    ```

    Malware on removable media may take advantage of Autorun features when the media is inserted into a system and execute.
  "
  desc  'check', "
    Run the following script to verify that `autorun-never=true` cannot be overridden:

    ```
    #!/usr/bin/env bash

    {
       # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\\n
       # determine system's package manager
       l_pkgoutput=\"\"
       if command -v dpkg-query > /dev/null 2>&1; then
          l_pq=\"dpkg-query -W\"
       elif command -v rpm > /dev/null 2>&1; then
          l_pq=\"rpm -q\"
       fi
       # Check if GDM is installed
       l_pcl=\"gdm gdm3\" # Space separated list of packages to check
       for l_pn in $l_pcl; do
          $l_pq \"$l_pn\" > /dev/null 2>&1 && l_pkgoutput=\"$l_pkgoutput\\n - Package: \\\"$l_pn\\\" exists on the system\\n - checking configuration\"
       done
       # Check configuration (If applicable)
       if [ -n \"$l_pkgoutput\" ]; then
          l_output=\"\" l_output2=\"\"
          echo -e \"$l_pkgoutput\\n\"
          # Look for idle-delay to determine profile in use, needed for remaining tests
          l_kfd=\"/etc/dconf/db/$(grep -Psril '^\\h*autorun-never\\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,\".\");print a[1]}').d\" #set directory of key file to be locked
          if [ -d \"$l_kfd\" ]; then # If key file directory doesn't exist, options can't be locked
             if grep -Priq '^\\h*\\/org/gnome\\/desktop\\/media-handling\\/autorun-never\\b' \"$l_kfd\"; then
                l_output=\"$l_output\\n - \\\"autorun-never\\\" is locked in \\\"$(grep -Pril '^\\h*\\/org/gnome\\/desktop\\/media-handling\\/autorun-never\\b' \"$l_kfd\")\\\"\"
             else
                l_output2=\"$l_output2\\n - \\\"autorun-never\\\" is not locked\"
             fi
          else
             l_output2=\"$l_output2\\n - \\\"autorun-never\\\" is not set so it can not be locked\"
          fi
       else
          l_output=\"$l_output\\n - GNOME Desktop Manager package is not installed on the system\\n  - Recommendation is not applicable\"
       fi
       # Report results. If no failures output in l_output2, we pass
       if [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n   PASS \\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to ensure that `autorun-never=true` cannot be overridden:

    ```
    #!/usr/bin/env bash

    {
       # Check if GNOME Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\\n
       # determine system's package manager
       l_pkgoutput=\"\"
       if command -v dpkg-query > /dev/null 2>&1; then
          l_pq=\"dpkg-query -W\"
       elif command -v rpm > /dev/null 2>&1; then
          l_pq=\"rpm -q\"
       fi
       # Check if GDM is installed
       l_pcl=\"gdm gdm3\" # Space separated list of packages to check
       for l_pn in $l_pcl; do
          $l_pq \"$l_pn\" > /dev/null 2>&1 && l_pkgoutput=\"y\" && echo -e \"\\n - Package: \\\"$l_pn\\\" exists on the system\\n - remediating configuration if needed\"
       done
       # Check configuration (If applicable)
       if [ -n \"$l_pkgoutput\" ]; then
          # Look for autorun to determine profile in use, needed for remaining tests
          l_kfd=\"/etc/dconf/db/$(grep -Psril '^\\h*autorun-never\\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,\".\");print a[1]}').d\" #set directory of key file to be locked
          if [ -d \"$l_kfd\" ]; then # If key file directory doesn't exist, options can't be locked
             if grep -Priq '^\\h*\\/org/gnome\\/desktop\\/media-handling\\/autorun-never\\b' \"$l_kfd\"; then
                echo \" - \\\"autorun-never\\\" is locked in \\\"$(grep -Pril '^\\h*\\/org/gnome\\/desktop\\/media-handling\\/autorun-never\\b' \"$l_kfd\")\\\"\"
             else
                echo \" - creating entry to lock \\\"autorun-never\\\"\"
                [ ! -d \"$l_kfd\"/locks ] && echo \"creating directory $l_kfd/locks\" && mkdir \"$l_kfd\"/locks
                {
                   echo -e '\\n# Lock desktop media-handling autorun-never setting'
                   echo '/org/gnome/desktop/media-handling/autorun-never'
                } >> \"$l_kfd\"/locks/00-media-autorun        
             fi
          else
             echo -e \" - \\\"autorun-never\\\" is not set so it can not be locked\\n - Please follow Recommendation \\\"Ensure GDM autorun-never is enabled\\\" and follow this Recommendation again\"
          fi
          # update dconf database
          dconf update
       else
          echo -e \" - GNOME Desktop Manager package is not installed on the system\\n  - Recommendation is not applicable\"
       fi
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AU-3 a', 'MP-7 (a)']
  tag cci:                   ['CCI-000130', 'CCI-002581']
  tag cis_rid:               '1.8.9'
  tag cis_number:            '1.8.9'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010809r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  gdm = package('gdm').installed?
  impact(gdm ? 0.5 : 0.0)
  describe command(%q{grep -Prs -- 'autorun-never' /etc/dconf/db/*/locks/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
  only_if('N/A: GDM display manager not installed (see 1.8.1)') { gdm }
end