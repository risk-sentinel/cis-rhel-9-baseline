# encoding: UTF-8

control 'C-1.3.1.8' do
  title 'Ensure SETroubleshoot is not installed'
  desc  "
    The SETroubleshoot service notifies desktop users of SELinux denials through a user-friendly interface. The service provides important information around configuration errors, unauthorized intrusions, and other potential errors.

    The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled.
  "
  desc  'rationale', "
    The SETroubleshoot service notifies desktop users of SELinux denials through a user-friendly interface. The service provides important information around configuration errors, unauthorized intrusions, and other potential errors.

    The SETroubleshoot service is an unnecessary daemon to have running on a server, especially if X Windows is disabled.
  "
  desc  'check', "
    Verify `setroubleshoot`  is not installed.

    Run the following command:

    ```
    # rpm -q setroubleshoot

    package setroubleshoot is not installed
    ```
  "
  desc  'fix', "
    Run the following command to uninstall `setroubleshoot`:

    ```
    # dnf remove setroubleshoot
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'AC-8 a']
  tag cci:                   ['CCI-000381', 'CCI-000051']
  tag cis_rid:               '1.3.1.8'
  tag cis_number:            '1.3.1.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01030108r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('setroubleshoot') do
    it { should_not be_installed }
  end
end