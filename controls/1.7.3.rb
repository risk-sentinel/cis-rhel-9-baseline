# encoding: UTF-8

control 'C-1.7.3' do
  title 'Ensure remote login warning banner is configured properly'
  desc  "
    The contents of the `/etc/issue.net`  file are displayed to users prior to login for remote connections from configured services.

    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If `mingetty(8)` supports the following options, they display operating system information:  `\\m`  - machine architecture `\\r`  - operating system release `\\s`  - operating system name `\\v`  - operating system version

    Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" `uname -a` \" command once they have logged in.
  "
  desc  'rationale', "
    The contents of the `/etc/issue.net`  file are displayed to users prior to login for remote connections from configured services.

    Unix-based systems have typically displayed information about the OS release and patch level upon logging in to the system. This information can be useful to developers who are developing software for a particular OS platform. If `mingetty(8)` supports the following options, they display operating system information:  `\\m`  - machine architecture `\\r`  - operating system release `\\s`  - operating system name `\\v`  - operating system version

    Warning messages inform users who are attempting to login to the system of their legal status regarding the system and must include the name of the organization that owns the system and any monitoring policies that are in place. Displaying OS and patch level information in login banners also has the side effect of providing detailed system information to attackers attempting to target specific exploits of a system. Authorized users can easily get this information by running the \" `uname -a` \" command once they have logged in.
  "
  desc  'check', "
    Run the following command and verify that the contents match site policy:

    ```
    # cat /etc/issue.net
    ```

    Run the following command and verify no results are returned:

    ```
    # grep -E -i \"(\\\\\\v|\\\\\\r|\\\\\\m|\\\\\\s|$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g'))\" /etc/issue.net
    ```
  "
  desc  'fix', "
    Edit the `/etc/issue.net`  file with the appropriate contents according to your site policy, remove any instances of `\\m` , `\\r` , `\\s` , `\\v` or references to the `OS platform`

    _Example:_

    ```
    # echo \"Authorized users only. All activity may be monitored and reported.\" > /etc/issue.net
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '1.7.3'
  tag cis_number:            '1.7.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010703r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -E -i 'red hat|rhel|kernel|release' /etc/issue.net 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end