# encoding: UTF-8

control 'C-5.3.1.3' do
  title 'Ensure latest version of libpwquality is installed'
  desc  "
    `libpwquality` provides common functions for password quality checking and scoring them based on their apparent randomness. The library also provides a function for generating random passwords with good pronounceability.

    This module can be plugged into the password stack of a given service to provide some plug-in strength-checking for passwords. The code was originally based on `pam_cracklib` module and the module is backwards compatible with its options.

    Strong passwords reduce the risk of systems being hacked through brute force methods.
  "
  desc  'rationale', "
    `libpwquality` provides common functions for password quality checking and scoring them based on their apparent randomness. The library also provides a function for generating random passwords with good pronounceability.

    This module can be plugged into the password stack of a given service to provide some plug-in strength-checking for passwords. The code was originally based on `pam_cracklib` module and the module is backwards compatible with its options.

    Strong passwords reduce the risk of systems being hacked through brute force methods.
  "
  desc  'check', "
    Run the following command to verify the version of `libpwquality` on the system:

    ```
    # rpm -q libpwquality
    ```

    Verify output is version `libpwquality-1.4.4-8` or greater:

    _Example:_ 

    ```
    libpwquality-1.4.4-8.el9.x86_64
    ```
  "
  desc  'fix', "
    Run the following command to install `libpwquality`:

    ```
    # dnf install libpwquality
    ```

    - IF - the version of `libpwquality` on the system is less that version `libpwquality-1.4.4-8`:

    Run the following command to update to the latest version of `libpwquality`:

    ```
    # dnf upgrade libpwquality
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.3.1.3'
  tag cis_number:            '5.3.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('libpwquality') do
    it { should be_installed }
  end
end