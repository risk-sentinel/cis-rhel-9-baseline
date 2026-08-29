# encoding: UTF-8

control 'C-5.3.1.1' do
  title 'Ensure latest version of pam is installed'
  desc  "
    Updated versions of PAM include additional functionality

    To ensure the system has full functionality and access to the options covered by this Benchmark, pam-1.5.1-19 or latter is required
  "
  desc  'rationale', "
    Updated versions of PAM include additional functionality

    To ensure the system has full functionality and access to the options covered by this Benchmark, pam-1.5.1-19 or latter is required
  "
  desc  'check', "
    Run the following command to verify the version of `PAM` on the system:

    ```
    # rpm -q pam
    ```

    Verify output is version `pam-1.5.1-19` or greater:

    _Example:_

    ```
    pam-1.5.1-19.el9.x86_64
    ```
  "
  desc  'fix', "
    - IF - the version of `PAM` on the system is less that version `pam-1.5.1-19`:

    Run the following command to update to the latest version of `PAM`:

    ```
    # dnf upgrade pam
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.3.1.1'
  tag cis_number:            '5.3.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('pam') do
    it { should be_installed }
  end
end