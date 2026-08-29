# encoding: UTF-8

control 'C-2.4.1.5' do
  title 'Ensure permissions on /etc/cron.weekly are configured'
  desc  "
    The `/etc/cron.weekly` directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the `crontab` command but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.

    Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  desc  'rationale', "
    The `/etc/cron.weekly` directory contains system cron jobs that need to run on a weekly basis. The files in this directory cannot be manipulated by the `crontab` command but are instead edited by system administrators using a text editor. The commands below restrict read/write and search access to user and group root, preventing regular users from accessing this directory.

    Granting write access to this directory for non-privileged users could provide them the means for gaining unauthorized elevated privileges. Granting read access to this directory could give an unprivileged user insight in how to gain elevated privileges or circumvent auditing controls.
  "
  desc  'check', "
    - IF - cron is installed on the system:

    Run the following command and verify `Uid`  and `Gid` are both `0/root` and `Access` does not grant permissions to `group` or `other`:

    ```
    # stat -Lc 'Access: (%a/%A) Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/cron.weekly/

    Access: (700/drwx------) Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    - IF - cron is installed on the system:

    Run the following commands to set ownership and permissions on the `/etc/cron.weekly` directory:

    ```
    # chown root:root /etc/cron.weekly/
    # chmod og-rwx /etc/cron.weekly/
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '2.4.1.5'
  tag cis_number:            '2.4.1.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-02040105r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe directory('/etc/cron.weekly') do
    it { should exist }
    its('mode') { should cmp '0700' }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end