# encoding: UTF-8

control 'C-1.7.6' do
  title 'Ensure access to /etc/issue.net is configured'
  desc  "
    The contents of the `/etc/issue.net`  file are displayed to users prior to login for remote connections from configured services.

    - IF - the `/etc/issue.net`  file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.
  "
  desc  'rationale', "
    The contents of the `/etc/issue.net`  file are displayed to users prior to login for remote connections from configured services.

    - IF - the `/etc/issue.net`  file does not have the correct access configured, it could be modified by unauthorized users with incorrect or misleading information.
  "
  desc  'check', "
    Run the following command and verify `Access` is `644` or more restrictive and `Uid`  and `Gid`  are both `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: { %g/ %G)' /etc/issue.net

    Access: (0644/-rw-r--r--)  Uid: ( 0/ root)   Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to set mode, owner, and group on `/etc/issue.net`:

    ```
    # chown root:root $(readlink -e /etc/issue.net)
    # chmod u-x,go-wx $(readlink -e /etc/issue.net)
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.7.6'
  tag cis_number:            '1.7.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010706r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/issue.net') do
    it { should exist }
    it { should_not be_more_permissive_than('0644') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end