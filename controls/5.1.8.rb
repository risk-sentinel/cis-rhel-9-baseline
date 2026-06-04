# encoding: UTF-8

control 'C-5.1.8' do
  title 'Ensure sshd Banner is configured'
  desc  "
    The `Banner` parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed.

    Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system.
  "
  desc  'rationale', "
    The `Banner` parameter specifies a file whose contents must be sent to the remote user before authentication is permitted. By default, no banner is displayed.

    Banners are used to warn connecting users of the particular site's policy regarding connection. Presenting a warning message prior to the normal user login may assist the prosecution of trespassers on the computer system.
  "
  desc  'check', "
    Run the following command to verify `Banner` is set:

    ```
    # sshd -T | grep -Pi -- '^banner\\h+\\/\\H+'
    ```

    _Example:_

    ```
    banner /etc/issue.net
    ```

    - IF - `Match` set statements are used in your environment, specify the connection parameters to use for the `-T` extended test mode and run the audit to verify the setting is not incorrectly configured in a match block

    _Example additional audit needed for a match block for the user `sshuser`:_

    ```
    # sshd -T -C user=sshuser | grep -Pi -- '^banner\\h+\\/\\H+'
    ```

    Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple `-C` options or as a comma-separated list. The keywords are `addr` (source address), `user` (user), `host` (resolved source host name), `laddr` (local address), `lport` (local port number), and `rdomain` (routing domain).

    Run the following command and verify that the contents or the file being called by the `Banner` argument match site policy:

    ```
    # [ -e \"$(sshd -T | awk '$1 == \"banner\" {print $2}')\" ] && cat \"$(sshd -T | awk '$1 == \"banner\" {print $2}')\"
    ``` 

    Run the following command and verify no results are returned:

    ```
    # grep -Psi -- \"(\\\\\\v|\\\\\\r|\\\\\\m|\\\\\\s|\\b$(grep '^ID=' /etc/os-release | cut -d= -f2 | sed -e 's/\"//g')\\b)\" \"$(sshd -T | awk '$1 == \"banner\" {print $2}')\"
    ```
  "
  desc  'fix', "
    Edit the `/etc/ssh/sshd_config` file to set the `Banner` parameter above any `Include` and `Match` entries as follows:

    ```
    Banner /etc/issue.net
    ```

    Note: First occurrence of a option takes precedence, Match set statements withstanding. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.

    Edit the file being called by the `Banner` argument with the appropriate contents according to your site policy, remove any instances of `\\m` , `\\r` , `\\s` , `\\v` or references to the `OS platform`

    _Example:_

    ```
    # printf '%s\\n' \"Authorized users only. All activity may be monitored and reported.\" > \"$(sshd -T | awk '$1 == \"banner\" {print $2}')\"
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.1.8'
  tag cis_number:            '5.1.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050108r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure sshd Banner is configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-050108r1_rule.'
  end
end
