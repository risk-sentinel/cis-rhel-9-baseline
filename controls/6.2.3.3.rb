# encoding: UTF-8

control 'C-6.2.3.3' do
  title 'Ensure journald is configured to send logs to rsyslog'
  desc  "
    Data from `systemd-journald` may be stored in volatile memory or persisted locally on the server.  Utilities exist to accept remote export of `systemd-journald` logs, however, use of the `rsyslog` service provides a consistent means of log collection and export.

    - IF - `rsyslog` is the preferred method for capturing logs, all logs of the system should be sent to it for further processing.
  "
  desc  'rationale', "
    Data from `systemd-journald` may be stored in volatile memory or persisted locally on the server.  Utilities exist to accept remote export of `systemd-journald` logs, however, use of the `rsyslog` service provides a consistent means of log collection and export.

    - IF - `rsyslog` is the preferred method for capturing logs, all logs of the system should be sent to it for further processing.
  "
  desc  'check', "
    - IF - `rsyslog` is the preferred method for capturing logs

    Run the following command to verify that logs are forwarded to `rsyslog` by setting  `ForwardToSyslog` to `yes` in the systemd-journald configuration:

    ```
    # systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E \"^ForwardToSyslog=yes\"

    ForwardToSyslog=yes
    ```
  "
  desc  'fix', "
    - IF - `rsyslog` is the preferred method for capturing logs:

    Set the following parameter in the `[Journal]` section in `/etc/systemd/journald.conf` or a file in `/etc/systemd/journald.conf.d/` ending in `.conf`:

    ```
    ForwardToSyslog=yes
    ```

    _Example:_
    ```
    #!/usr/bin/env bash

    {
       [ ! -d /etc/systemd/journald.conf.d/ ] && mkdir /etc/systemd/journald.conf.d/
       if grep -Psq -- '^\\h*\\[Journal\\]' /etc/systemd/journald.conf.d/60-journald.conf; then
          printf '%s\\n' \"ForwardToSyslog=yes\" >> /etc/systemd/journald.conf.d/60-journald.conf
       else
          printf '%s\\n' \"[Journal]\" \"ForwardToSyslog=yes\" >> /etc/systemd/journald.conf.d/60-journald.conf
       fi
    }
    ```

    Note: If this setting appears in a canonically later file, or later in the same file, the setting will be overwritten

    Run to following command to update the parameters in the service:


    Restart `systemd-journald.service`:

    ```
    # systemctl reload-or-restart systemd-journald.service
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a', 'AU-5 b']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123', 'CCI-000140']
  tag cis_rid:               '6.2.3.3'
  tag cis_number:            '6.2.3.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020303r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  impact 0.5
  describe 'journald forwards to rsyslog (6.2.3.3)' do
    skip 'operational: applies only when rsyslog is the primary pipeline (mutually exclusive with 6.2.2.2 journald-only); consumer logging-architecture choice.'
  end
end