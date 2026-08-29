# encoding: UTF-8

control 'C-1.8.5' do
  title 'Ensure GDM screen locks cannot be overridden'
  desc  "
    GNOME Desktop Manager can make the screen lock automatically whenever the user is idle for some amount of time.

    By using the lockdown mode in dconf, you can prevent users from changing specific settings.

    To lock down a dconf key or subpath,  create a locks subdirectory in the keyfile directory. The files inside this directory contain a list of keys or subpaths to lock. Just as with the keyfiles, you may add any number of files to this directory.

    _Example Lock File:_

    ```
    # Lock desktop screensaver settings
    /org/gnome/desktop/session/idle-delay
    /org/gnome/desktop/screensaver/lock-delay
    ```

    Setting a lock-out value reduces the window of opportunity for unauthorized user access to another user's session that has been left unattended.

    Without locking down the system settings, user settings take precedence over the system settings.
  "
  desc  'rationale', "
    GNOME Desktop Manager can make the screen lock automatically whenever the user is idle for some amount of time.

    By using the lockdown mode in dconf, you can prevent users from changing specific settings.

    To lock down a dconf key or subpath,  create a locks subdirectory in the keyfile directory. The files inside this directory contain a list of keys or subpaths to lock. Just as with the keyfiles, you may add any number of files to this directory.

    _Example Lock File:_

    ```
    # Lock desktop screensaver settings
    /org/gnome/desktop/session/idle-delay
    /org/gnome/desktop/screensaver/lock-delay
    ```

    Setting a lock-out value reduces the window of opportunity for unauthorized user access to another user's session that has been left unattended.

    Without locking down the system settings, user settings take precedence over the system settings.
  "
  desc  'check', "
    Run the following script to verify that the screen lock cannot be overridden:

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
          # Look for idle-delay to determine profile in use, needed for remaining tests
          l_kfd=\"/etc/dconf/db/$(grep -Psril '^\\h*idle-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,\".\");print a[1]}').d\" #set directory of key file to be locked
          l_kfd2=\"/etc/dconf/db/$(grep -Psril '^\\h*lock-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,\".\");print a[1]}').d\" #set directory of key file to be locked
          if [ -d \"$l_kfd\" ]; then # If key file directory doesn't exist, options can't be locked
             if grep -Prilq '\\/org\\/gnome\\/desktop\\/session\\/idle-delay\\b' \"$l_kfd\"; then
                l_output=\"$l_output\\n - \\\"idle-delay\\\" is locked in \\\"$(grep -Pril '\\/org\\/gnome\\/desktop\\/session\\/idle-delay\\b' \"$l_kfd\")\\\"\"
             else
                l_output2=\"$l_output2\\n - \\\"idle-delay\\\" is not locked\"
             fi
          else
             l_output2=\"$l_output2\\n - \\\"idle-delay\\\" is not set so it can not be locked\"
          fi
          if [ -d \"$l_kfd2\" ]; then # If key file directory doesn't exist, options can't be locked
             if grep -Prilq '\\/org\\/gnome\\/desktop\\/screensaver\\/lock-delay\\b' \"$l_kfd2\"; then
                l_output=\"$l_output\\n - \\\"lock-delay\\\" is locked in \\\"$(grep -Pril '\\/org\\/gnome\\/desktop\\/screensaver\\/lock-delay\\b' \"$l_kfd2\")\\\"\"
             else
                l_output2=\"$l_output2\\n - \\\"lock-delay\\\" is not locked\"
             fi
          else
             l_output2=\"$l_output2\\n - \\\"lock-delay\\\" is not set so it can not be locked\"
          fi
       else
          l_output=\"$l_output\\n - GNOME Desktop Manager package is not installed on the system\\n  - Recommendation is not applicable\"
       fi
       # Report results. If no failures output in l_output2, we pass
    	[ -n \"$l_pkgoutput\" ] && echo -e \"\\n$l_pkgoutput\"
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
    Run the following script to ensure screen locks cannot be overridden:

    ```
    #!/usr/bin/env bash

    {
       # Check if GNMOE Desktop Manager is installed.  If package isn't installed, recommendation is Not Applicable\\n
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
          # Look for idle-delay to determine profile in use, needed for remaining tests
          l_kfd=\"/etc/dconf/db/$(grep -Psril '^\\h*idle-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,\".\");print a[1]}').d\" #set directory of key file to be locked
          # Look for lock-delay to determine profile in use, needed for remaining tests
          l_kfd2=\"/etc/dconf/db/$(grep -Psril '^\\h*lock-delay\\h*=\\h*uint32\\h+\\d+\\b' /etc/dconf/db/*/ | awk -F'/' '{split($(NF-1),a,\".\");print a[1]}').d\" #set directory of key file to be locked
          if [ -d \"$l_kfd\" ]; then # If key file directory doesn't exist, options can't be locked
             if grep -Prilq '^\\h*\\/org\\/gnome\\/desktop\\/session\\/idle-delay\\b' \"$l_kfd\"; then
                echo \" - \\\"idle-delay\\\" is locked in \\\"$(grep -Pril '^\\h*\\/org\\/gnome\\/desktop\\/session\\/idle-delay\\b' \"$l_kfd\")\\\"\"
             else
                echo \"creating entry to lock \\\"idle-delay\\\"\"
                [ ! -d \"$l_kfd\"/locks ] && echo \"creating directory $l_kfd/locks\" && mkdir \"$l_kfd\"/locks
                {
                   echo -e '\\n# Lock desktop screensaver idle-delay setting'
                   echo '/org/gnome/desktop/session/idle-delay'
                } >> \"$l_kfd\"/locks/00-screensaver        
             fi
          else
             echo -e \" - \\\"idle-delay\\\" is not set so it can not be locked\\n - Please follow Recommendation \\\"Ensure GDM screen locks when the user is idle\\\" and follow this Recommendation again\"
          fi
          if [ -d \"$l_kfd2\" ]; then # If key file directory doesn't exist, options can't be locked
             if grep -Prilq '^\\h*\\/org\\/gnome\\/desktop\\/screensaver\\/lock-delay\\b' \"$l_kfd2\"; then
                echo \" - \\\"lock-delay\\\" is locked in \\\"$(grep -Pril '^\\h*\\/org\\/gnome\\/desktop\\/screensaver\\/lock-delay\\b' \"$l_kfd2\")\\\"\"
             else
                echo \"creating entry to lock \\\"lock-delay\\\"\"
                [ ! -d \"$l_kfd2\"/locks ] && echo \"creating directory $l_kfd2/locks\" && mkdir \"$l_kfd2\"/locks
                {
                   echo -e '\\n# Lock desktop screensaver lock-delay setting'
                   echo '/org/gnome/desktop/screensaver/lock-delay'
                } >> \"$l_kfd2\"/locks/00-screensaver       
             fi
          else
             echo -e \" - \\\"lock-delay\\\" is not set so it can not be locked\\n - Please follow Recommendation \\\"Ensure GDM screen locks when the user is idle\\\" and follow this Recommendation again\"
          fi
       else
          echo -e \" - GNOME Desktop Manager package is not installed on the system\\n  - Recommendation is not applicable\"
       fi
    }
    ```

    Run the following command to update the system databases:

    ```
    # dconf update
    ```
    Note: Users must log out and back in again before the system-wide settings take effect.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-11 b', 'SA-11 e']
  tag cci:                   ['CCI-000056', 'CCI-003178']
  tag cis_rid:               '1.8.5'
  tag cis_number:            '1.8.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010805r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  applicable = package('gdm').installed?
  impact 0.5
  impact 0.0 unless applicable
  describe command(%q{grep -Prs -- '(idle-delay|lock-delay)' /etc/dconf/db/*/locks/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
  only_if('N/A: GDM display manager not installed (see 1.8.1)') { applicable }
end