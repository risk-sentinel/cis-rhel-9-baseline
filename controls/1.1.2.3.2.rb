# encoding: UTF-8

control 'C-1.1.2.3.2' do
  title 'Ensure nodev option set on /home partition'
  desc  "
    The `nodev` mount option specifies that the filesystem cannot contain special devices.

    Since the `/home` filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in `/home`.
  "
  desc  'rationale', "
    The `nodev` mount option specifies that the filesystem cannot contain special devices.

    Since the `/home` filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in `/home`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/home`, verify that the `nodev` option is set.

    Run the following command to verify that the `nodev` mount option is set.

    _Example:_

    ```
    # findmnt -kn /home | grep -v nodev

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/home`.

    Edit the `/etc/fstab` file and add `nodev` to the fourth field (mounting options) for the `/home` partition.

    _Example:_

    ``` /home defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/home` with the configured options:

    ```
    # mount -o remount /home
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.3.2'
  tag cis_number:            '1.1.2.3.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020302r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe mount('/home') do
    it { should be_mounted }
    its('options') { should include 'nodev' }
  end
end