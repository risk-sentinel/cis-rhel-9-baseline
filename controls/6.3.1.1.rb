# encoding: UTF-8

control 'C-6.3.1.1' do
  title 'Ensure auditd packages are installed'
  desc  "
    `auditd` is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk.

    The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
  "
  desc  'rationale', "
    `auditd` is the userspace component to the Linux Auditing System. It's responsible for writing audit records to the disk.

    The capturing of system events provides system administrators with information to allow them to determine if unauthorized access to their system is occurring.
  "
  desc  'check', "
    Run the following command and verify `audit` and `audit-libs` packages are installed:

    ``` 
    # rpm -q audit audit-libs

    audit- audit-libs- ```
  "
  desc  'fix', "
    Run the following command to install `audit` and `audit-libs`:

    ```
    # dnf install audit audit-libs
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-12 c', 'AU-12 a', 'AU-2 a', 'AU-3 (1)', 'AU-3 d', 'AU-3 f', 'AU-3 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AU-12 a', 'AU-12 c', 'AU-2 a', 'AU-3', 'AU-3 (1)']
  tag cci:                   ['CCI-000172', 'CCI-000169', 'CCI-000123', 'CCI-000135', 'CCI-000133', 'CCI-001487', 'CCI-000131']
  tag cis_rid:               '6.3.1.1'
  tag cis_number:            '6.3.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe package('audit') do
    it { should be_installed }
  end
  describe package('audit-libs') do
    it { should be_installed }
  end
end