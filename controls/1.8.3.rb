# encoding: UTF-8

control 'C-1.8.3' do
  title 'Ensure GDM disable-user-list option is enabled'
  desc  "
    GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.

    The `disable-user-list` option controls if a list of users is displayed on the login screen

    Displaying the user list eliminates half of the Userid/Password equation that an unauthorized person would need to log on.
  "
  desc  'rationale', "
    GDM is the GNOME Display Manager which handles graphical login for GNOME based systems.

    The `disable-user-list` option controls if a list of users is displayed on the login screen

    Displaying the user list eliminates half of the Userid/Password equation that an unauthorized person would need to log on.
  "
  desc  'check', "
    Run the following script and to verify that the `disable-user-list` option is enabled or GNOME isn't installed:

    ```
    #!/usr/bin/env bash

    {
       l_pkgoutput=\"\"
       if command -v dpkg-query > /dev/null 2>&1; then
          l_pq=\"dpkg-query -W\"
       elif command -v rpm > /dev/null 2>&1; then
          l_pq=\"rpm -q\"
       fi
       l_pcl=\"gdm gdm3\" # Space separated list of packages to check
       for l_pn in $l_pcl; do
          $l_pq \"$l_pn\" > /dev/null 2>&1 && l_pkgoutput=\"$l_pkgoutput\\n - Package: \\\"$l_pn\\\" exists on the system\\n - checking configuration\"
       done
       if [ -n \"$l_pkgoutput\" ]; then
          output=\"\" output2=\"\"
          l_gdmfile=\"$(grep -Pril '^\\h*disable-user-list\\h*=\\h*true\\b' /etc/dconf/db)\"
          if [ -n \"$l_gdmfile\" ]; then
             output=\"$output\\n - The \\\"disable-user-list\\\" option is enabled in \\\"$l_gdmfile\\\"\"
             l_gdmprofile=\"$(awk -F\\/ '{split($(NF-1),a,\".\");print a[1]}' <<< \"$l_gdmfile\")\"
             if grep -Pq \"^\\h*system-db:$l_gdmprofile\" /etc/dconf/profile/\"$l_gdmprofile\"; then
                output=\"$output\\n - The \\\"$l_gdmprofile\\\" exists\"
             else
                output2=\"$output2\\n - The \\\"$l_gdmprofile\\\" doesn't exist\"
             fi
             if [ -f \"/etc/dconf/db/$l_gdmprofile\" ]; then
                output=\"$output\\n - The \\\"$l_gdmprofile\\\" profile exists in the dconf database\"
             else
                output2=\"$output2\\n - The \\\"$l_gdmprofile\\\" profile doesn't exist in the dconf database\"
             fi
          else
             output2=\"$output2\\n - The \\\"disable-user-list\\\" option is not enabled\"
          fi
          if [ -z \"$output2\" ]; then
             echo -e \"$l_pkgoutput\\n- Audit result:\\n   * PASS: *\\n$output\\n\"
          else
             echo -e \"$l_pkgoutput\\n- Audit Result:\\n   * FAIL: *\\n$output2\\n\"
             [ -n \"$output\" ] && echo -e \"$output\\n\"
          fi
       else
          echo -e \"\\n\\n - GNOME Desktop Manager isn't installed\\n - Recommendation is Not Applicable\\n- Audit result:\\n  * PASS *\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to enable the `disable-user-list` option:

    Note: the `l_gdm_profile` variable in the script can be changed if a different profile name is desired in accordance with local site policy.

    ```
    #!/usr/bin/env bash

    {
       l_gdmprofile=\"gdm\"
       if [ ! -f \"/etc/dconf/profile/$l_gdmprofile\" ]; then
          echo \"Creating profile \\\"$l_gdmprofile\\\"\"
          echo -e \"user-db:user\\nsystem-db:$l_gdmprofile\\nfile-db:/usr/share/$l_gdmprofile/greeter-dconf-defaults\" > /etc/dconf/profile/$l_gdmprofile
       fi
       if [ ! -d \"/etc/dconf/db/$l_gdmprofile.d/\" ]; then
          echo \"Creating dconf database directory \\\"/etc/dconf/db/$l_gdmprofile.d/\\\"\"
          mkdir /etc/dconf/db/$l_gdmprofile.d/
       fi
       if ! grep -Piq '^\\h*disable-user-list\\h*=\\h*true\\b' /etc/dconf/db/$l_gdmprofile.d/*; then
          echo \"creating gdm keyfile for machine-wide settings\"
          if ! grep -Piq -- '^\\h*\\[org\\/gnome\\/login-screen\\]' /etc/dconf/db/$l_gdmprofile.d/*; then
             echo -e \"\\n[org/gnome/login-screen]\\n# Do not show the user list\\ndisable-user-list=true\" >> /etc/dconf/db/$l_gdmprofile.d/00-login-screen
          else
             sed -ri '/^\\s*\\[org\\/gnome\\/login-screen\\]/ a\\# Do not show the user list\\ndisable-user-list=true' $(grep -Pil -- '^\\h*\\[org\\/gnome\\/login-screen\\]' /etc/dconf/db/$l_gdmprofile.d/*)
          fi
       fi
       dconf update
    }
    ```

    Note: When the user profile is created or changed, the user will need to log out and log in again before the changes will be applied.

     - OR -

    Run the following command to remove the GNOME package:

    ```
    # dnf remove gdm
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '1.8.3'
  tag cis_number:            '1.8.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010803r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  applicable = package('gdm').installed?
  impact 0.5
  impact 0.0 unless applicable
  describe command(%q{grep -Prs -- 'disable-user-list=true' /etc/dconf/db/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
  only_if('N/A: GDM display manager not installed (see 1.8.1)') { applicable }
end