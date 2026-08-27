# encoding: UTF-8

control 'C-1.1.2.2.2' do
  title 'Ensure nodev option set on /dev/shm partition'
  desc  "
    The `nodev` mount option specifies that the filesystem cannot contain special devices.

    Since the `/dev/shm` filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in `/dev/shm` partitions.
  "
  desc  'rationale', "
    The `nodev` mount option specifies that the filesystem cannot contain special devices.

    Since the `/dev/shm` filesystem is not intended to support devices, set this option to ensure that users cannot attempt to create special devices in `/dev/shm` partitions.
  "
  desc  'check', "
    - IF - a separate partition exists for `/dev/shm`, verify that the `nodev` option is set.

    ```
    # findmnt -kn /dev/shm | grep -v 'nodev'

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/dev/shm`.

    Edit the `/etc/fstab` file and add `nodev` to the fourth field (mounting options) for the `/dev/shm`  partition. See the `fstab(5)` manual page for more information.

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
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.2.2'
  tag cis_number:            '1.1.2.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: assert nodev where /dev/shm is a distinct mount; ephemeral
  # renders N/A when /dev/shm is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/dev/shm')
    impact 0.0
    describe '/dev/shm nodev isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/dev/shm').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/dev/shm') do
      it { should be_mounted }
      its('options') { should include 'nodev' }
    end
  end
end
