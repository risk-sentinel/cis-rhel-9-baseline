# encoding: UTF-8

control 'C-7.1.6' do
  title 'Ensure permissions on /etc/shadow- are configured'
  desc  "
    The `/etc/shadow-` file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.

    It is critical to ensure that the `/etc/shadow-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'rationale', "
    The `/etc/shadow-` file is used to store backup information about user accounts that is critical to the security of those accounts, such as the hashed password and other security information.

    It is critical to ensure that the `/etc/shadow-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'check', "
    Run the following command to verify `/etc/shadow-` is mode 000, `Uid` is `0/root` and `Gid` is `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)'  /etc/shadow-

    Access: (0/----------)  Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to set mode, owner, and group on `/etc/shadow-`:

    ```
    # chown root:root /etc/shadow-
    # chmod 0000 /etc/shadow-
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.6'
  tag cis_number:            '7.1.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070106r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure permissions on /etc/shadow- are configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070106r1_rule.'
  end
end
