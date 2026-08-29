# encoding: UTF-8

control 'C-1.7.4' do
  title 'Ensure access to /etc/motd is configured'
  desc  "
    The contents of the `/etc/motd`  file are displayed to users after login and function as a message of the day for authenticated users.

    - IF - the `/etc/motd`  file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.
  "
  desc  'rationale', "
    The contents of the `/etc/motd`  file are displayed to users after login and function as a message of the day for authenticated users.

    - IF - the `/etc/motd`  file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.
  "
  desc  'check', "
    Run the following command and verify that if `/etc/motd` exists, `Access` is `644` or more restrictive, `Uid` and `Gid`  are both `0/root`:

    ```
    # [ -e /etc/motd ] && stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: { %g/ %G)' /etc/motd

    Access: (0644/-rw-r--r--)  Uid: ( 0/ root) Gid: ( 0/ root)
      -- OR --
    Nothing is returned
    ```
  "
  desc  'fix', "
    Run the following commands to set mode, owner, and group on `/etc/motd`:

    ```
    # chown root:root $(readlink -e /etc/motd)
    # chmod u-x,go-wx $(readlink -e /etc/motd)
    ```

     - OR -

    Run the following command to remove the `/etc/motd` file:

    ```
    # rm /etc/motd
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.7.4'
  tag cis_number:            '1.7.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010704r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/motd') do
    it { should exist }
    it { should_not be_more_permissive_than('0644') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end