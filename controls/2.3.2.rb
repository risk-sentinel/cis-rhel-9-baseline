# encoding: UTF-8

control 'C-2.3.2' do
  title 'Ensure chrony is configured'
  desc  "
    `chrony` is a daemon which implements the Network Time Protocol (NTP) and is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on `chrony` can be found at . `chrony` can be configured to be a client and/or a server.

    If `chrony` is in use on the system proper configuration is vital to ensuring time synchronization is working properly.
  "
  desc  'rationale', "
    `chrony` is a daemon which implements the Network Time Protocol (NTP) and is designed to synchronize system clocks across a variety of systems and use a source that is highly accurate. More information on `chrony` can be found at . `chrony` can be configured to be a client and/or a server.

    If `chrony` is in use on the system proper configuration is vital to ensuring time synchronization is working properly.
  "
  desc  'check', "
    Run the following command and verify remote server is configured properly:

    ```
    # grep -Prs -- '^\\h*(server|pool)\\h+[^#\\n\\r]+' /etc/chrony.conf /etc/chrony.d/

    server ```

    Multiple servers may be configured.
  "
  desc  'fix', "
    Add or edit server or pool lines to `/etc/chrony.conf` or a file in the `/etc/chrony.d` directory as appropriate:

    _Example:_

    ```
    server ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-45 (1) (b)', 'SC-45 (2) (b)', 'SC-45 (1) (a)']
  tag nist_r4:               ['AU-8 (1)', 'AU-8 (2)']
  tag cci:                   ['CCI-004926', 'CCI-004929', 'CCI-004923']
  tag cis_rid:               '2.3.2'
  tag cis_number:            '2.3.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020302r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe file('/etc/chrony.conf') do
    it { should exist }
    its('content') { should match(/^\s*(server|pool)\s+\S+/) }
  end
end