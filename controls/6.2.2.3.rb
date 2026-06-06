# encoding: UTF-8

control 'C-6.2.2.3' do
  title 'Ensure journald Compress is configured'
  desc  "
    The journald system includes the capability of compressing overly large files to avoid filling up the system with logs or making the logs unmanageably large.

    Uncompressed large files may unexpectedly fill a filesystem leading to resource unavailability.  Compressing logs prior to write can prevent sudden, unexpected filesystem impacts.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'rationale', "
    The journald system includes the capability of compressing overly large files to avoid filling up the system with logs or making the logs unmanageably large.

    Uncompressed large files may unexpectedly fill a filesystem leading to resource unavailability.  Compressing logs prior to write can prevent sudden, unexpected filesystem impacts.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'check', "
    Run the following command to verify `Compress` is set to `yes`:

    ```
    # systemd-analyze cat-config systemd/journald.conf systemd/journald.conf.d/* | grep -E \"^Compress=yes\"

    Compress=yes
    ```
  "
  desc  'fix', "
    Set the following parameter in the `[Journal]` section in `/etc/systemd/journald.conf` or a file in `/etc/systemd/journald.conf.d/` ending in `.conf`:

    ```
    Compress=yes
    ```

    _Example:_
    ```
    #!/usr/bin/env bash

    {
       [ ! -d /etc/systemd/journald.conf.d/ ] && mkdir /etc/systemd/journald.conf.d/
       if grep -Psq -- '^\\h*\\[Journal\\]' /etc/systemd/journald.conf.d/60-journald.conf; then
          printf '%s\\n' \"Compress=yes\" >> /etc/systemd/journald.conf.d/60-journald.conf
       else
          printf '%s\\n' \"[Journal]\" \"Compress=yes\" >> /etc/systemd/journald.conf.d/60-journald.conf
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
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AC-2 (2)', 'AU-2 a', 'AU-4']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-001682', 'CCI-000123', 'CCI-001848']
  tag cis_rid:               '6.2.2.3'
  tag cis_number:            '6.2.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -rhEi '^\s*Compress\s*=\s*yes' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end