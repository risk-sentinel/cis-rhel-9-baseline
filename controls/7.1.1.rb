# encoding: UTF-8

control 'C-7.1.1' do
  title 'Ensure permissions on /etc/passwd are configured'
  desc  "
    The `/etc/passwd` file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.

    It is critical to ensure that the `/etc/passwd` file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'rationale', "
    The `/etc/passwd` file contains user account information that is used by many system utilities and therefore must be readable for these utilities to operate.

    It is critical to ensure that the `/etc/passwd` file is protected from unauthorized write access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'check', "
    Run the following command to verify `/etc/passwd` is mode 644 or more restrictive, `Uid` is `0/root` and `Gid` is `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)'  /etc/passwd

    Access: (0644/-rw-r--r--)  Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to remove excess permissions, set owner, and set group on `/etc/passwd`:

    ```
    # chmod u-x,go-wx /etc/passwd
    # chown root:root /etc/passwd
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.1'
  tag cis_number:            '7.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/passwd') do
    it { should exist }
    it { should_not be_more_permissive_than('0644') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end