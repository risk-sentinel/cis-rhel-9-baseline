# encoding: UTF-8

control 'C-1.1.2.7.4' do
  title 'Ensure noexec option set on /var/log/audit partition'
  desc  "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/var/log/audit` filesystem is only intended for audit logs, set this option to ensure that users cannot run executable binaries from `/var/log/audit`.
  "
  desc  'rationale', "
    The `noexec` mount option specifies that the filesystem cannot contain executable binaries.

    Since the `/var/log/audit` filesystem is only intended for audit logs, set this option to ensure that users cannot run executable binaries from `/var/log/audit`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/var/log/audit`, verify that the `noexec` option is set.

    Run the following command to verify that the `noexec` mount option is set.

    _Example:_

    ```
    # findmnt -kn /var/log/audit | grep -v noexec

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/var/log/audit`.

    Edit the `/etc/fstab` file and add `noexec` to the fourth field (mounting options) for the `/var/log/audit` partition.

    _Example:_

    ``` /var/log/audit defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/var/log/audit` with the configured options:

    ```
    # mount -o remount /var/log/audit
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.7.4'
  tag cis_number:            '1.1.2.7.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020704r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe mount('/var/log/audit') do
    it { should be_mounted }
    its('options') { should include 'noexec' }
  end
end