# encoding: UTF-8

control 'C-1.1.2.3.1' do
  title 'Ensure separate partition exists for /home'
  desc  "
    The `/home` directory is used to support disk storage needs of local users.

    The default installation only creates a single `/` partition. Since the `/home` directory contains user generated data, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to `/home` and impact all local users.

    Configuring `/home` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attacker's ability to create exploits on the system. In the case of `/home` options such as `usrquota/grpquota` may be considered to limit the impact that users can have on each other with regards to disk resource exhaustion. Other options allow for specific behavior. See `man mount` for exact details regarding filesystem-independent and filesystem-specific options.

    As `/home` contains user data, care should be taken to ensure the security and integrity of the data and mount point.
  "
  desc  'rationale', "
    The `/home` directory is used to support disk storage needs of local users.

    The default installation only creates a single `/` partition. Since the `/home` directory contains user generated data, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole. In addition, other operations on the system could fill up the disk unrelated to `/home` and impact all local users.

    Configuring `/home` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attacker's ability to create exploits on the system. In the case of `/home` options such as `usrquota/grpquota` may be considered to limit the impact that users can have on each other with regards to disk resource exhaustion. Other options allow for specific behavior. See `man mount` for exact details regarding filesystem-independent and filesystem-specific options.

    As `/home` contains user data, care should be taken to ensure the security and integrity of the data and mount point.
  "
  desc  'check', "
    Run the following command and verify output shows `/home` is mounted:

    ```
    # findmnt -kn /home

    /home   /dev/sdb  ext4  rw,nosuid,nodev,noexec,relatime,seclabel
    ```
  "
  desc  'fix', "
    For new installations, during installation create a custom partition setup and specify a separate partition for `/home`.

    For systems that were previously installed, create a new partition and configure `/etc/fstab` as appropriate.
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.1.2.3.1'
  tag cis_number:            '1.1.2.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis (#4): strict when /home is a distinct mount; ephemeral renders
  # N/A when /home is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/home')
    impact 0.0
    describe '/home separate-mount isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/home').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/home') do
      it { should be_mounted }
    end
  end
end
