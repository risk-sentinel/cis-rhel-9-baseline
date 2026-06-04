# encoding: UTF-8

control 'C-1.3.1.1' do
  title 'Ensure SELinux is installed'
  desc  "
    SELinux provides Mandatory Access Control.

    Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available.
  "
  desc  'rationale', "
    SELinux provides Mandatory Access Control.

    Without a Mandatory Access Control system installed only the default Discretionary Access Control system will be available.
  "
  desc  'check', "
    Verify SELinux is installed.

    Run the following command:

    ```
    # rpm -q libselinux

    libselinux- ```
  "
  desc  'fix', "
    Run the following command to install `SELinux`:

    ```
    # dnf install libselinux
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.3.1.1'
  tag cis_number:            '1.3.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01030101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure SELinux is installed' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-01030101r1_rule.'
  end
end
