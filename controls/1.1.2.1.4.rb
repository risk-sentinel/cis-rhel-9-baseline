# encoding: UTF-8

control 'C-1.1.2.1.4' do
  title 'Ensure noexec option set on /tmp partition'
  desc  "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/tmp` filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from `/tmp`.
  "
  desc  'rationale', "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/tmp` filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from `/tmp`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/tmp`, verify that the `noexec` option is set.

    Run the following command to verify that the `noexec` mount option is set.

    _Example:_

    ```
    # findmnt -kn /tmp | grep -v noexec

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/tmp`.

    Edit the `/etc/fstab` file and add `noexec` to the fourth field (mounting options) for the `/tmp` partition.

    _Example:_

    ``` /tmp defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/tmp` with the configured options:

    ```
    # mount -o remount /tmp
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.1.4'
  tag cis_number:            '1.1.2.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe mount('/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end