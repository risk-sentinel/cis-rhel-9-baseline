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
  tag nist:                  ['AU-12 c', 'AU-12 a', 'AU-2 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AU-12 a', 'AU-12 c', 'AU-2 a']
  tag cci:                   ['CCI-000172', 'CCI-000169', 'CCI-000123']
  tag cis_rid:               '6.2.3.1'
  tag cis_number:            '6.2.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe package('rsyslog') do
    it { should be_installed }
  end
end