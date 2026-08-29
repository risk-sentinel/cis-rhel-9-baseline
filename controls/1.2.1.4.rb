# encoding: UTF-8

control 'C-1.2.1.4' do
  title 'Ensure package manager repositories are configured'
  desc  "
    Systems need to have the respective package manager repositories configured to ensure that the system is able to receive the latest patches and updates.

    If a system's package repositories are misconfigured, important patches may not be identified or a rogue repository could introduce compromised software.
  "
  desc  'rationale', "
    Systems need to have the respective package manager repositories configured to ensure that the system is able to receive the latest patches and updates.

    If a system's package repositories are misconfigured, important patches may not be identified or a rogue repository could introduce compromised software.
  "
  desc  'check', "
    Run the following command to verify repositories are configured correctly. The output may vary depending on which repositories are currently configured on the system.

    _Example:_

    ```
    # dnf repolist
    Last metadata expiration check: 1:00:00 ago on Mon 1 Jan 2021 00:00:00 BST.
    repo id        repo name                        status
    *fedora        Fedora 28 - x86_64               57,327
    *updates       Fedora 28 - x86_64 - Updates     22,133
    ```

    For the repositories in use, inspect the configuration file to ensure all settings are correctly applied according to site policy.

    _Example:_

    Depending on the distribution being used the repo file name might differ.

    ```
    cat /etc/yum.repos.d/*.repo

    ```
  "
  desc  'fix', "
    Configure your package manager repositories according to site policy.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-12', 'MP-6 a', 'SI-2 a']
  tag ksi:                   ['KSI-CMT-VTD', 'KSI-RPL-ABO']
  tag nist_r4:               ['MP-6 a', 'SI-12', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001028', 'CCI-001225']
  tag cis_rid:               '1.2.1.4'
  tag cis_number:            '1.2.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01020104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  impact 0.5
  describe 'package manager repositories configured (1.2.1.4)' do
    skip 'operational: the set of enabled yum/dnf repositories is site-specific (internal mirrors, satellite); operator attests repos point to authorized sources.'
  end
end