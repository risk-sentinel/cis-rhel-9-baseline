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
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a', 'AU-3 a']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'AU-3', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123', 'CCI-000130']
  tag cis_rid:               '6.3.1.1'
  tag cis_number:            '6.3.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('audit') do
    it { should be_installed }
  end
  describe package('audit-libs') do
    it { should be_installed }
  end
end