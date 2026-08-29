# encoding: UTF-8

control 'C-1.1.2.1.2' do
  title 'Ensure nodev option set on /tmp partition'
  desc  "
    The `nodev` mount option specifies that the filesystem cannot contain special devices.

    Since the `/tmp` filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in `/tmp`.
  "
  desc  'rationale', "
    The `nodev` mount option specifies that the filesystem cannot contain special devices.

    Since the `/tmp` filesystem is not intended to support devices, set this option to ensure that users cannot create a block or character special devices in `/tmp`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/tmp`, verify that the `nodev` option is set.

    Run the following command to verify that the `nodev` mount option is set.

    _Example:_

    ```
    # findmnt -kn /tmp | grep -v nodev

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/tmp`.

    Edit the `/etc/fstab` file and add `nodev` to the fourth field (mounting options) for the `/tmp` partition.

    _Example:_

    ``` /tmp defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/tmp` with the configured options:

    ```
    # mount -o remount /tmp
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.1.2.1.2'
  tag cis_number:            '1.1.2.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: assert nodev where /tmp is a distinct mount; ephemeral
  # renders N/A when /tmp is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/tmp')
    impact 0.0
    describe '/tmp nodev isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/tmp').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/tmp') do
      it { should be_mounted }
      its('options') { should include 'nodev' }
    end
  end
end
