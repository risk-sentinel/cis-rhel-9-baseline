# encoding: UTF-8

control 'C-1.1.2.3.3' do
  title 'Ensure nosuid option set on /home partition'
  desc  "
    The `nosuid` mount option specifies that the filesystem cannot contain `setuid`  files.

    Since the `/home` filesystem is only intended for user file storage, set this option to ensure that users cannot create `setuid` files in `/home`.
  "
  desc  'rationale', "
    The `nosuid` mount option specifies that the filesystem cannot contain `setuid`  files.

    Since the `/home` filesystem is only intended for user file storage, set this option to ensure that users cannot create `setuid` files in `/home`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/home`, verify that the `nosuid` option is set.

    Run the following command to verify that the `nosuid` mount option is set.

    _Example:_

    ```
    # findmnt -kn /home | grep -v nosuid

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/home`.

    Edit the `/etc/fstab` file and add `nosuid` to the fourth field (mounting options) for the `/home` partition.

    _Example:_

    ``` /home defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/home` with the configured options:

    ```
    # mount -o remount /home
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.3.3'
  tag cis_number:            '1.1.2.3.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020303r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: assert nosuid where /home is a distinct mount; ephemeral
  # renders N/A when /home is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/home')
    impact 0.0
    describe '/home nosuid isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/home').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/home') do
      it { should be_mounted }
      its('options') { should include 'nosuid' }
    end
  end
end
