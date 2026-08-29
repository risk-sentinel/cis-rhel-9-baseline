# encoding: UTF-8

control 'C-7.1.8' do
  title 'Ensure permissions on /etc/gshadow- are configured'
  desc  "
    The `/etc/gshadow-` file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.

    It is critical to ensure that the `/etc/gshadow-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'rationale', "
    The `/etc/gshadow-` file is used to store backup information about groups that is critical to the security of those accounts, such as the hashed password and other security information.

    It is critical to ensure that the `/etc/gshadow-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'check', "
    Run the following command to verify `/etc/gshadow-` is mode 000, `Uid` is `0/root` and `Gid` is `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)'  /etc/gshadow-

    Access: (0/----------)  Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to set mode, owner, and group on `/etc/gshadow-`:

    ```
    # chown root:root /etc/gshadow-
    # chmod 0000 /etc/gshadow-
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'CM-8 a 1']
  tag nist_r4:               ['AC-3', 'CM-8 a 1']
  tag cci:                   ['CCI-000213', 'CCI-000389']
  tag cis_rid:               '7.1.8'
  tag cis_number:            '7.1.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070108r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/gshadow-') do
    it { should exist }
    it { should_not be_more_permissive_than('0000') }
    its('owner') { should eq 'root' }
    its('group') { should be_in %w(root shadow) }
  end
end