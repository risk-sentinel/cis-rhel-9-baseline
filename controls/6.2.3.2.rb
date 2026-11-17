# encoding: UTF-8

control 'C-6.2.3.2' do
  title 'Ensure rsyslog service is enabled and active'
  desc  "
    Once the `rsyslog`  package is installed, ensure that the service is enabled.

    If the `rsyslog` service is not enabled to start on boot, the system will not capture logging events.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `journald` is used.
  "
  desc  'rationale', "
    Once the `rsyslog`  package is installed, ensure that the service is enabled.

    If the `rsyslog` service is not enabled to start on boot, the system will not capture logging events.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `journald` is used.
  "
  desc  'check', "
    - IF - `rsyslog` is being used for logging on the system:

    Run the following command to verify `rsyslog.service` is enabled:

    ```
    # systemctl is-enabled rsyslog

    enabled
    ```

    Run the following command to verify `rsyslog.service` is active:

    ```
    # systemctl is-active rsyslog.service

    active
    ```
  "
  desc  'fix', "
    - IF - `rsyslog` is being used for logging on the system:

    Run the following commands to unmask, enable, and start `rsyslog.service`:

    ```
    # systemctl unmask rsyslog.service
    # systemctl enable rsyslog.service
    # systemctl start rsyslog.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-12 c', 'AU-12 a', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AU-12 a', 'AU-12 c', 'AU-2 a']
  tag cci:                   ['CCI-000172', 'CCI-000169', 'CCI-000123']
  tag cis_rid:               '6.2.3.2'
  tag cis_number:            '6.2.3.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020302r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe service('rsyslog') do
    it { should be_enabled }
    it { should be_running }
  end
end