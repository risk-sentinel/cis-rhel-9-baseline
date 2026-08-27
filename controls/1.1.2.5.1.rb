# encoding: UTF-8

control 'C-1.1.2.5.1' do
  title 'Ensure separate partition exists for /var/tmp'
  desc  "
    The `/var/tmp` directory is a world-writable directory used for temporary storage by all users and some applications. Temporary files residing in `/var/tmp` are to be preserved between reboots.

    The default installation only creates a single `/` partition. Since the `/var/tmp` directory is world-writable, there is a risk of resource exhaustion. In addition, other operations on the system could fill up the disk unrelated to `/var/tmp` and cause potential disruption to daemons as the disk is full.

    Configuring `/var/tmp` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attacker's ability to create exploits on the system.
  "
  desc  'rationale', "
    The `/var/tmp` directory is a world-writable directory used for temporary storage by all users and some applications. Temporary files residing in `/var/tmp` are to be preserved between reboots.

    The default installation only creates a single `/` partition. Since the `/var/tmp` directory is world-writable, there is a risk of resource exhaustion. In addition, other operations on the system could fill up the disk unrelated to `/var/tmp` and cause potential disruption to daemons as the disk is full.

    Configuring `/var/tmp` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attacker's ability to create exploits on the system.
  "
  desc  'check', "
    Run the following command and verify output shows `/var/tmp` is mounted.

    _Example:_

    ```
    # findmnt -kn /var/tmp

    /var/tmp   /dev/sdb ext4   rw,nosuid,nodev,noexec,relatime,seclabel
    ```
  "
  desc  'fix', "
    For new installations, during installation create a custom partition setup and specify a separate partition for `/var/tmp`.

    For systems that were previously installed, create a new partition and configure `/etc/fstab` as appropriate.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.5.1'
  tag cis_number:            '1.1.2.5.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020501r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: strict when /var/tmp is a distinct mount; ephemeral renders
  # N/A when /var/tmp is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/var/tmp')
    impact 0.0
    describe '/var/tmp separate-mount isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/var/tmp').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/var/tmp') do
      it { should be_mounted }
    end
  end
end
