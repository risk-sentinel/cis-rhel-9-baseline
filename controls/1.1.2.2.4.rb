# encoding: UTF-8

control 'C-1.1.2.2.4' do
  title 'Ensure noexec option set on /dev/shm partition'
  desc  "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.
  "
  desc  'rationale', "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Setting this option on a file system prevents users from executing programs from shared memory. This deters users from introducing potentially malicious software on the system.
  "
  desc  'check', "
    - IF - a separate partition exists for `/dev/shm`, verify that the `noexec` option is set.

    ```
    # findmnt -kn /dev/shm | grep -v 'noexec'

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/dev/shm`.

    Edit the `/etc/fstab` file and add `noexec` to the fourth field (mounting options) for the `/dev/shm` partition.

    _Example:_

    ```
    tmpfs /dev/shm    tmpfs     defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/dev/shm` with the configured options:

    ```
    # mount -o remount /dev/shm
    ```

    Note: It is recommended to use `tmpfs` as the device/filesystem type as `/dev/shm` is used as shared memory space by applications.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.2.4'
  tag cis_number:            '1.1.2.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe mount('/dev/shm') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end