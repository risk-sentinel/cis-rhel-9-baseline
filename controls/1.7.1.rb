# encoding: UTF-8

control 'C-1.7.1' do
  title 'Ensure message of the day is configured properly'
  desc  "
    The contents of the `/etc/motd`  file are displayed to users after login and function as a message of the day for authenticated users.

    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If `mingetty(8)` supports the following options, they display operating system information: `\\m`  - machine architecture `\\r`  - operating system release `\\s`  - operating system name `\\v`  - operating system version

    Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" `uname -a` \" command once they have logged in.
  "
  desc  'rationale', "
    The contents of the `/etc/motd`  file are displayed to users after login and function as a message of the day for authenticated users.

    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If `mingetty(8)` supports the following options, they display operating system information: `\\m`  - machine architecture `\\r`  - operating system release `\\s`  - operating system name `\\v`  - operating system version

    Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" `uname -a` \" command once they have logged in.
  "
  desc  'check', "
    Run the following script to verify `MOTD` files do not contain system information:
 
    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       a_files=()
       for l_file in /etc/motd{,.d/*}; do
          if grep -Psqi -- \"(\\\\\\v|\\\\\\r|\\\\\\m|\\\\\\s|\\b$(grep ^ID= /etc/os-release | cut -d= -f2 | sed -e 's/\"//g')\\b)\" \"$l_file\"; then
             l_output2=\"$l_output2\\n - File: \\\"$l_file\\\" includes system information\"
          else
             a_files+=(\"$l_file\")
          fi
       done
       if [ \"${#a_files[@]}\" -gt 0 ]; then
          echo -e \"\\n-   Please review the following files and verify their contents follow local site policy \\n\"
          printf '%s\\n' \"${a_files[@]}\"
       elif [ -z \"$l_output2\" ]; then
          echo -e \"-  No MOTD files with any size were found. Please verify this conforms to local site policy  -\"
       fi
       if [ -z \"$l_output2\" ]; then
          l_output=\" - No MOTD files include system information\"
          echo -e \"\\n- Audit Result:\\n   PASS \\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\\n\"
       fi
    }
    ```

    Review any files returned and verify that they follow local site policy
  "
  desc  'fix', "
    Edit the file found in `/etc/motd.d/*` with the appropriate contents according to your site policy, remove any instances of `\\m` , `\\r` , `\\s` , `\\v` or references to the `OS platform`

    - OR -

    - IF - the `motd` is not used, this file can be removed.

    Run the following command to remove the `motd` file:

    ```
    # rm /etc/motd
    ```

    Run the following script and review and/or update all returned files' contents to:
    - Remove all system information (`\\v`, `\\r`; `\\m`, `\\s`)
    - Remove any refence to the operating system
    - Ensure contents follow local site policy

    ```
    #!/usr/bin/env bash

    {
       a_files=()
       for l_file in /etc/motd{,.d/*}; do
          if grep -Psqi -- \"(\\\\\\v|\\\\\\r|\\\\\\m|\\\\\\s|\\b$(grep ^ID= /etc/os-release | cut -d= -f2 | sed -e 's/\"//g')\\b)\" \"$l_file\"; then
             echo -e \"\\n - File: \\\"$l_file\\\" includes system information. Edit this file to remove these entries\"
          else
          a_files+=(\"$l_file\")
          fi
       done
       if [ \"${#a_files[@]}\" -gt 0 ]; then
          echo -e \"\\n-   Please review the following files and verify their contents follow local site policy \\n\"
          printf '%s\\n' \"${a_files[@]}\"
       fi
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '1.7.1'
  tag cis_number:            '1.7.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010701r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -E -i 'red hat|rhel|kernel|release' /etc/motd 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end