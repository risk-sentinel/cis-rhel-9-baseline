# encoding: UTF-8

control 'C-5.1.18' do
  title 'Ensure sshd MaxSessions is configured'
  desc  "
    The `MaxSessions` parameter specifies the maximum number of open sessions permitted from a given connection.

    To protect a system from denial of service due to a large number of concurrent sessions, use the rate limiting function of MaxSessions to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  desc  'rationale', "
    The `MaxSessions` parameter specifies the maximum number of open sessions permitted from a given connection.

    To protect a system from denial of service due to a large number of concurrent sessions, use the rate limiting function of MaxSessions to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  desc  'check', "
    Run the following command and verify that `MaxSessions` is `10` or less:

    ```
    # sshd -T | grep -i maxsessions

    maxsessions 10
    ```

    Run the following command and verify the output:

    ```
    grep -Psi -- '^\\h*MaxSessions\\h+\\\"?(1[1-9]|[2-9][0-9]|[1-9][0-9][0-9]+)\\b' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf

    Nothing should be returned
    ```

    - IF - `Match` set statements are used in your environment, specify the connection parameters to use for the `-T` extended test mode and run the audit to verify the setting is not incorrectly configured in a match block

    _Example additional audit needed for a match block for the user `sshuser`:_

    ```
    # sshd -T -C user=sshuser | grep maxsessions
    ```

    Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple `-C` options or as a comma-separated list. The keywords are `addr` (source address), `user` (user), `host` (resolved source host name), `laddr` (local address), `lport` (local port number), and `rdomain` (routing domain)
  "
  desc  'fix', "
    Edit the `/etc/ssh/sshd_config` file to set the `MaxSessions` parameter to `10` or less above any `Include` and `Match` entries as follows:

    ```
    MaxSessions 10
    ```

    Note: First occurrence of an option takes precedence, `Match` set statements withstanding. If `Include` locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in `Include` location.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.1.18'
  tag cis_number:            '5.1.18'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050118r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe sshd_config do
    its('MaxSessions') { should cmp <= 10 }
  end
end