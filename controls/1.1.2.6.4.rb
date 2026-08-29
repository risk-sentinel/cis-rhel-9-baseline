# encoding: UTF-8

control 'C-1.1.2.6.4' do
  title 'Ensure noexec option set on /var/log partition'
  desc  "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/var/log` filesystem is only intended for log files, set this option to ensure that users cannot run executable binaries from `/var/log`.
  "
  desc  'rationale', "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/var/log` filesystem is only intended for log files, set this option to ensure that users cannot run executable binaries from `/var/log`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/var/log`, verify that the `noexec` option is set.

    Run the following command to verify that the `noexec` mount option is set.

    _Example:_

    ```
    # findmnt -kn /var/log | grep -v noexec

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/var/log`.

    Edit the `/etc/fstab` file and add `noexec` to the fourth field (mounting options) for the `/var/log` partition.

    _Example:_

    ``` /var/log defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/var/log` with the configured options:

    ```
    # mount -o remount /var/log
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.6.4'
  tag cis_number:            '1.1.2.6.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020604r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: assert noexec where /var/log is a distinct mount; ephemeral
  # renders N/A when /var/log is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/var/log')
    impact 0.0
    describe '/var/log noexec isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/var/log').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/var/log') do
      it { should be_mounted }
      its('options') { should include 'noexec' }
    end
  end
end
