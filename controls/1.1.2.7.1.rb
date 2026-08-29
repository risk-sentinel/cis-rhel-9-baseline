# encoding: UTF-8

control 'C-1.1.2.7.1' do
  title 'Ensure separate partition exists for /var/log/audit'
  desc  "
    The auditing daemon, `auditd`, stores log data in the `/var/log/audit` directory.

    The default installation only creates a single `/` partition. Since the `/var/log/audit` directory contains the `audit.log` file which can grow quite large, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to `/var/log/audit` and cause `auditd` to trigger its `space_left_action` as the disk is full. See `man auditd.conf` for details.

    Configuring `/var/log/audit` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attacker's ability to create exploits on the system. Other options allow for specific behavior. See `man mount` for exact details regarding filesystem-independent and filesystem-specific options.

    As `/var/log/audit` contains audit logs, care should be taken to ensure the security and integrity of the data and mount point.
  "
  desc  'rationale', "
    The auditing daemon, `auditd`, stores log data in the `/var/log/audit` directory.

    The default installation only creates a single `/` partition. Since the `/var/log/audit` directory contains the `audit.log` file which can grow quite large, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to `/var/log/audit` and cause `auditd` to trigger its `space_left_action` as the disk is full. See `man auditd.conf` for details.

    Configuring `/var/log/audit` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attacker's ability to create exploits on the system. Other options allow for specific behavior. See `man mount` for exact details regarding filesystem-independent and filesystem-specific options.

    As `/var/log/audit` contains audit logs, care should be taken to ensure the security and integrity of the data and mount point.
  "
  desc  'check', "
    Run the following command and verify output shows `/var/log/audit` is mounted:

    ```
    # findmnt -kn /var/log/audit

    /var/log/audit /dev/sdb ext4   rw,nosuid,nodev,noexec,relatime,seclabel
    ```
  "
  desc  'fix', "
    For new installations, during installation create a custom partition setup and specify a separate partition for `/var/log/audit`.

    For systems that were previously installed, create a new partition and configure `/etc/fstab` as appropriate.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_rid:               '1.1.2.7.1'
  tag cis_number:            '1.1.2.7.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020701r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: strict when /var/log/audit is a distinct mount; ephemeral renders
  # N/A when /var/log/audit is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/var/log/audit')
    impact 0.0
    describe '/var/log/audit separate-mount isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/var/log/audit').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/var/log/audit') do
      it { should be_mounted }
    end
  end
end
