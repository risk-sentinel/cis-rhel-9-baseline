# encoding: UTF-8

control 'C-1.1.2.6.1' do
  title 'Ensure separate partition exists for /var/log'
  desc  "
    The `/var/log`  directory is used by system services to store log data.

    The default installation only creates a single `/` partition. Since the `/var/log` directory contains log files which can grow quite large, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole.

    Configuring `/var/log` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attackers ability to create exploits on the system. Other options allow for specific behavior. See `man mount` for exact details regarding filesystem-independent and filesystem-specific options.

    As `/var/log` contains log files, care should be taken to ensure the security and integrity of the data and mount point.
  "
  desc  'rationale', "
    The `/var/log`  directory is used by system services to store log data.

    The default installation only creates a single `/` partition. Since the `/var/log` directory contains log files which can grow quite large, there is a risk of resource exhaustion. It will essentially have the whole disk available to fill up and impact the system as a whole.

    Configuring `/var/log` as its own file system allows an administrator to set additional mount options such as `noexec/nosuid/nodev`. These options limit an attackers ability to create exploits on the system. Other options allow for specific behavior. See `man mount` for exact details regarding filesystem-independent and filesystem-specific options.

    As `/var/log` contains log files, care should be taken to ensure the security and integrity of the data and mount point.
  "
  desc  'check', "
    Run the following command and verify output shows `/var/log`  is mounted:

    ```
    # findmnt -kn /var/log

    /var/log /dev/sdb ext4   rw,nosuid,nodev,noexec,relatime,seclabel
    ```
  "
  desc  'fix', "
    For new installations, during installation create a custom partition setup and specify a separate partition for `/var/log` .

    For systems that were previously installed, create a new partition and configure `/etc/fstab`  as appropriate.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_rid:               '1.1.2.6.1'
  tag cis_number:            '1.1.2.6.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020601r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure separate partition exists for /var/log' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-0101020601r1_rule.'
  end
end
