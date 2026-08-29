# encoding: UTF-8

control 'C-6.2.3.1' do
  title 'Ensure rsyslog is installed'
  desc  "
    The `rsyslog` software is recommended in environments where `journald` does not meet operation requirements.

    The security enhancements of `rsyslog` such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server) justify installing and configuring the package.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `journald` is used.
  "
  desc  'rationale', "
    The `rsyslog` software is recommended in environments where `journald` does not meet operation requirements.

    The security enhancements of `rsyslog` such as connection-oriented (i.e. TCP) transmission of logs, the option to log to database formats, and the encryption of log data en route to a central logging server) justify installing and configuring the package.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `journald` is used.
  "
  desc  'check', "
    - IF - `rsyslog` is being used for logging on the system:

    Run the following command to verify `rsyslog` is installed:

    ```
    # rpm -q rsyslog
    ```

    Verify the output matches:

    ```
    rsyslog- ```
  "
  desc  'fix', "
    Run the following command to install `rsyslog`:

    ```
    # dnf install rsyslog
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.3.1'
  tag cis_number:            '6.2.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('rsyslog') do
    it { should be_installed }
  end
end