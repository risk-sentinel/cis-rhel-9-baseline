# encoding: UTF-8

control 'C-6.2.1.1' do
  title 'Ensure journald service is enabled and active'
  desc  "
    Ensure that the `systemd-journald` service is enabled to allow capturing of logging events.

    If the `systemd-journald` service is not enabled to start on boot, the system will not capture logging events.
  "
  desc  'rationale', "
    Ensure that the `systemd-journald` service is enabled to allow capturing of logging events.

    If the `systemd-journald` service is not enabled to start on boot, the system will not capture logging events.
  "
  desc  'check', "
    Run the following command to verify `systemd-journald` is enabled:

    ```
    # systemctl is-enabled systemd-journald.service

    static
    ```

    Note: By default the `systemd-journald` service does not have an `[Install]` section and thus cannot be enabled / disabled. It is meant to be referenced as `Requires` or `Wants` by other unit files. As such, if the status of `systemd-journald` is not `static`, investigate why

    Run the following command to verify `systemd-journald` is active:

    ```
    # systemctl is-active systemd-journald.service

    active
    ```
  "
  desc  'fix', "
    Run the following commands to unmask and start `systemd-journald.service`

    ```
    # systemctl unmask systemd-journald.service
    # systemctl start systemd-journald.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.1.1'
  tag cis_number:            '6.2.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('systemd-journald') do
    it { should be_enabled }
    it { should be_running }
  end
end