# encoding: UTF-8

control 'C-6.2.2.2' do
  title 'Ensure journald ForwardToSyslog is disabled'
  desc  "
    Data from `journald` should be kept in the confines of the service and not forwarded to other services.

    - IF - `journald` is the method for capturing logs, all logs of the system should be handled by `journald` and not forwarded to other logging mechanisms.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'rationale', "
    Data from `journald` should be kept in the confines of the service and not forwarded to other services.

    - IF - `journald` is the method for capturing logs, all logs of the system should be handled by `journald` and not forwarded to other logging mechanisms.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'check', "
    - IF - `journald` is the method for capturing logs

    Run the following command to verify `ForwardToSyslog` is set to `no`:

    ```
    # systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E \"^ForwardToSyslog=no\"

    ForwardToSyslog=no
    ```
  "
  desc  'fix', "
    - IF - `rsyslog` is the preferred method for capturing logs, this section and Recommendation should be skipped and the \"Configure rsyslog\" section followed.

    - IF - `journald` is the preferred method for capturing logs:

    Set the following parameter in the `[Journal]` section in `/etc/systemd/journald.conf` or a file in /etc/systemd/journald.conf.d/ ending in `.conf`:

    ```
    ForwardToSyslog=no
    ```

    _Example:_
    ```
    #!/usr/bin/env bash

    {
       [ ! -d /etc/systemd/journald.conf.d/ ] && mkdir /etc/systemd/journald.conf.d/
       if grep -Psq -- '^\\h*\\[Journal\\]' /etc/systemd/journald.conf.d/60-journald.conf; then
          printf '%s\\n' \"ForwardToSyslog=no\" >> /etc/systemd/journald.conf.d/60-journald.conf
       else
          printf '%s\\n' \"[Journal]\" \"ForwardToSyslog=no\" >> /etc/systemd/journald.conf.d/60-journald.conf
       fi
    }
    ```

    Note: If this setting appears in a canonically later file, or later in the same file, the setting will be overwritten

    Run to following command to update the parameters in the service:

    ```
    # systemctl reload-or-restart systemd-journald
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['IA-2 (2)', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.2.2'
  tag cis_number:            '6.2.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhEi '^\s*ForwardToSyslog\s*=\s*no' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end