# encoding: UTF-8

control 'C-6.1.1' do
  title 'Ensure AIDE is installed'
  desc  "
    Advanced Intrusion Detection Environment (AIDE) is a intrusion detection tool that uses predefined rules to check the integrity of files and directories in the Linux operating system. AIDE has its own database to check the integrity of files and directories.  

    `aide` takes a snapshot of files and directories including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.

    By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries.
  "
  desc  'rationale', "
    Advanced Intrusion Detection Environment (AIDE) is a intrusion detection tool that uses predefined rules to check the integrity of files and directories in the Linux operating system. AIDE has its own database to check the integrity of files and directories.  

    `aide` takes a snapshot of files and directories including modification times, permissions, and file hashes which can then be used to compare against the current state of the filesystem to detect modifications to the system.

    By monitoring the filesystem state compromised files can be detected to prevent or limit the exposure of accidental or malicious misconfigurations or modified binaries.
  "
  desc  'check', "
    Run the following command and verify `aide`  is installed:

    ```
    # rpm -q aide

    aide- ```
  "
  desc  'fix', "
    Run the following command to install `aide`:

    ```
    # dnf install aide
    ```

    Configure `aide` as appropriate for your environment. Consult the `aide` documentation for options.

    Initialize `aide`:

    Run the following commands:

    ```
    # aide --init
    ```

    ```
    # mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AU-2 a', 'SC-12 (3)']
  tag cci:                   ['CCI-000123', 'CCI-002447']
  tag cis_rid:               '6.1.1'
  tag cis_number:            '6.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-060101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe package('aide') do
    it { should be_installed }
  end
end