# encoding: UTF-8

control 'C-1.1.2.4.3' do
  title 'Ensure nosuid option set on /var partition'
  desc  "
    The `nosuid` mount option specifies that the filesystem cannot contain `setuid` files.

    Since the `/var` filesystem is only intended for variable files such as logs, set this option to ensure that users cannot create `setuid` files in `/var`.
  "
  desc  'rationale', "
    The `nosuid` mount option specifies that the filesystem cannot contain `setuid` files.

    Since the `/var` filesystem is only intended for variable files such as logs, set this option to ensure that users cannot create `setuid` files in `/var`.
  "
  desc  'check', "
    - IF - a separate partition exists for `/var`, verify that the `nosuid` option is set.

    Run the following command to verify that the `nosuid` mount option is set.

    _Example:_

    ```
    # findmnt -kn /var | grep -v nosuid

    Nothing should be returned
    ```
  "
  desc  'fix', "
    - IF - a separate partition exists for `/var`.

    Edit the `/etc/fstab` file and add `nosuid` to the fourth field (mounting options) for the `/var` partition.

    _Example:_

    ``` /var defaults,rw,nosuid,nodev,noexec,relatime  0 0
    ```

    Run the following command to remount `/var` with the configured options:

    ```
    # mount -o remount /var
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.4.3'
  tag cis_number:            '1.1.2.4.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020403r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: assert nosuid where /var is a distinct mount; ephemeral
  # renders N/A when /var is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/var')
    impact 0.0
    describe '/var nosuid isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/var').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/var') do
      it { should be_mounted }
      its('options') { should include 'nosuid' }
    end
  end
end
