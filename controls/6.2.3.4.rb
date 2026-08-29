# encoding: UTF-8

control 'C-6.2.3.4' do
  title 'Ensure rsyslog log file creation mode is configured'
  desc  "
    `rsyslog` will create logfiles that do not already exist on the system.

    The `$FileCreateMode` parameter allows you to specify the creation mode with which `rsyslog` creates new files. If not specified, the value 0644 is used (which retains backward-compatibility with earlier releases). The value given must always be a 4-digit octal number, with the initial digit being zero.

    Please note that the actual permission depend on rsyslogd's process umask. 

    `$FileCreateMode` may be specified multiple times. If so, it specifies the creation mode for all selector lines that follow until the next $FileCreateMode parameter. Order of lines is vitally important.

    It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'rationale', "
    `rsyslog` will create logfiles that do not already exist on the system.

    The `$FileCreateMode` parameter allows you to specify the creation mode with which `rsyslog` creates new files. If not specified, the value 0644 is used (which retains backward-compatibility with earlier releases). The value given must always be a 4-digit octal number, with the initial digit being zero.

    Please note that the actual permission depend on rsyslogd's process umask. 

    `$FileCreateMode` may be specified multiple times. If so, it specifies the creation mode for all selector lines that follow until the next $FileCreateMode parameter. Order of lines is vitally important.

    It is important to ensure that log files have the correct permissions to ensure that sensitive data is archived and protected.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'check', "
    Run the following command 

    Run the following command to verify `$FileCreateMode`: 

    ```
    # grep -Ps '^\\h*\\$FileCreateMode\\h+0[0,2,4,6][0,2,4]0\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    ```

    Verify the output is includes 0640 or more restrictive:

    ```
    $FileCreateMode 0640 
    ```

    Should a site policy dictate less restrictive permissions, ensure to follow said policy.

    Note: More restrictive permissions such as `0600` is implicitly sufficient.
  "
  desc  'fix', "
    Edit either `/etc/rsyslog.conf` or a dedicated `.conf` file in `/etc/rsyslog.d/` and set `$FileCreateMode` to `0640` or more restrictive:

    ```
    $FileCreateMode 0640
    ```

    Restart the service:

    ```
    # systemctl restart rsyslog
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-2 a', 'AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag cci:                   ['CCI-000213', 'CCI-002110', 'CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.3.4'
  tag cis_number:            '6.2.3.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020304r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE '^\s*\$FileCreateMode\s+0[0-6][0-4]0' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end