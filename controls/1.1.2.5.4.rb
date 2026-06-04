# encoding: UTF-8

control 'C-1.1.2.5.4' do
  title 'Ensure noexec option set on /var/tmp partition'
  desc  "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/var/tmp` filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from `/var/tmp`.
  "
  desc  'rationale', "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/var/tmp` filesystem is only intended for temporary file storage, set this option to ensure that users cannot run executable binaries from `/var/tmp`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/var/tmp`, verify that the `noexec` option is set.

    Run the following command to verify that the `noexec` mount option is set.

    _Example:_

    ```
    # findmnt -kn /var/tmp | grep -v noexec

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/var/tmp`.

    Edit the `/etc/fstab` file and add `noexec` to the fourth field (mounting options) for the `/var/tmp` partition.

    _Example:_

    ``` /var/tmp defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/var/tmp` with the configured options:

    ```
    # mount -o remount /var/tmp
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.5.4'
  tag cis_number:            '1.1.2.5.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020504r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe mount('/var/tmp') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end