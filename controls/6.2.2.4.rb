# encoding: UTF-8

control 'C-6.2.2.4' do
  title 'Ensure journald Storage is configured'
  desc  "
    Data from journald may be stored in volatile memory or persisted locally on the server.  Logs in memory will be lost upon a system reboot.  By persisting logs to local disk on the server they are protected from loss due to a reboot.

    Writing log data to disk will provide the ability to forensically reconstruct events which may have impacted the operations or security of a system even after a system crash or reboot.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'rationale', "
    Data from journald may be stored in volatile memory or persisted locally on the server.  Logs in memory will be lost upon a system reboot.  By persisting logs to local disk on the server they are protected from loss due to a reboot.

    Writing log data to disk will provide the ability to forensically reconstruct events which may have impacted the operations or security of a system even after a system crash or reboot.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'check', "
    Run the following command to verify `Storage` is set to `persistent`:
    ```
    # systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E \"^Storage=persistent\"

    Storage=persistent
    ```
  "
  desc  'fix', "
    Set the following parameter in the `[Journal]` section in `/etc/systemd/journald.conf` or a file in `/etc/systemd/journald.conf.d/` ending in `.conf`:

    ```
    Storage=persistent
    ```

    _Example:_
    ```
    #!/usr/bin/env bash

    {
       [ ! -d /etc/systemd/journald.conf.d/ ] && mkdir /etc/systemd/journald.conf.d/
       if grep -Psq -- '^\\h*\\[Journal\\]' /etc/systemd/journald.conf.d/60-journald.conf; then
          printf '%s\\n' \"Storage=persistent\" >> /etc/systemd/journald.conf.d/60-journald.conf
       else
          printf '%s\\n' \"[Journal]\" \"Storage=persistent\" >> /etc/systemd/journald.conf.d/60-journald.conf
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
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.2.4'
  tag cis_number:            '6.2.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhEi '^\s*Storage\s*=\s*persistent' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end