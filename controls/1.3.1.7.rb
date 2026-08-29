# encoding: UTF-8

control 'C-1.3.1.7' do
  title 'Ensure the MCS Translation Service (mcstrans) is not installed'
  desc  "
    The `mcstransd` daemon provides category label information to client processes requesting information. The label translations are defined in `/etc/selinux/targeted/setrans.conf`

    Since this service is not used very often, remove it to reduce the amount of potentially vulnerable code running on the system.
  "
  desc  'rationale', "
    The `mcstransd` daemon provides category label information to client processes requesting information. The label translations are defined in `/etc/selinux/targeted/setrans.conf`

    Since this service is not used very often, remove it to reduce the amount of potentially vulnerable code running on the system.
  "
  desc  'check', "
    Run the following command and verify `mcstrans` is not installed. 

    ```
    # rpm -q mcstrans

    package mcstrans is not installed
    ```
  "
  desc  'fix', "
    Run the following command to uninstall `mcstrans`:

    ```
    # dnf remove mcstrans
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.3.1.7'
  tag cis_number:            '1.3.1.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01030107r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('mcstrans') do
    it { should_not be_installed }
  end
end