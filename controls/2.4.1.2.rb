# encoding: UTF-8

control 'C-2.4.1.2' do
  title 'Ensure permissions on /etc/crontab are configured'
  desc  "
    The `/etc/crontab` file is used by `cron` to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and that only the owner can access the file.

    This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access.
  "
  desc  'rationale', "
    The `/etc/crontab` file is used by `cron` to control its own jobs. The commands in this item make sure that root is the user and group owner of the file and that only the owner can access the file.

    This file contains information on what system jobs are run by cron. Write access to these files could provide unprivileged users with the ability to elevate their privileges. Read access to these files could provide users with the ability to gain insight on system jobs that run on the system and could provide them a way to gain unauthorized privileged access.
  "
  desc  'check', "
    - IF - cron is installed on the system:

    Run the following command and verify `Uid` and `Gid` are both `0/root`  and `Access` does not grant permissions to `group` or `other` :

    ```
    # stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/crontab

    Access: (600/-rw-------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    - IF - cron is installed on the system:

    Run the following commands to set ownership and permissions on `/etc/crontab`:

    ```
    # chown root:root /etc/crontab
    # chmod og-rwx /etc/crontab
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '2.4.1.2'
  tag cis_number:            '2.4.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-02040102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/crontab') do
    it { should exist }
    its('mode') { should cmp '0600' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end