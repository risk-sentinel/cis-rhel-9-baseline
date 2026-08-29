# encoding: UTF-8

control 'C-1.1.2.2.3' do
  title 'Ensure nosuid option set on /dev/shm partition'
  desc  "
    The `nosuid` mount option specifies that the filesystem cannot contain `setuid`  files.

    Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.
  "
  desc  'rationale', "
    The `nosuid` mount option specifies that the filesystem cannot contain `setuid`  files.

    Setting this option on a file system prevents users from introducing privileged programs onto the system and allowing non-root users to execute them.
  "
  desc  'check', "
    - IF - a separate partition exists for `/dev/shm`, verify that the `nosuid` option is set.

    ```
    # findmnt -kn /dev/shm | grep -v 'nosuid'

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/dev/shm`.

    Edit the `/etc/fstab` file and add `nosuid` to the fourth field (mounting options) for the `/dev/shm`  partition. See the `fstab(5)` manual page for more information.

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
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.2.3'
  tag cis_number:            '1.1.2.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: assert nosuid where /dev/shm is a distinct mount; ephemeral
  # renders N/A when /dev/shm is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/dev/shm')
    impact 0.0
    describe '/dev/shm nosuid isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/dev/shm').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/dev/shm') do
      it { should be_mounted }
      its('options') { should include 'nosuid' }
    end
  end
end
