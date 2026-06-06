# encoding: UTF-8

control 'C-7.1.4' do
  title 'Ensure permissions on /etc/group- are configured'
  desc  "
    The `/etc/group-` file contains a backup list of all the valid groups defined in the system.

    It is critical to ensure that the `/etc/group-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'rationale', "
    The `/etc/group-` file contains a backup list of all the valid groups defined in the system.

    It is critical to ensure that the `/etc/group-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'check', "
    Run the following command to verify `/etc/group-` is mode 644 or more restrictive, `Uid` is `0/root` and `Gid` is `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)'  /etc/group-

    Access: (0644/-rw-r--r--)  Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to remove excess permissions, set owner, and set group on `/etc/group-`:

    ```
    # chmod u-x,go-wx /etc/group-
    # chown root:root /etc/group-
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.4'
  tag cis_number:            '7.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe file('/etc/group-') do
    it { should exist }
    it { should_not be_more_permissive_than('0644') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end