# encoding: UTF-8

control 'C-7.1.3' do
  title 'Ensure permissions on /etc/group are configured'
  desc  "
    The `/etc/group` file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.

    The `/etc/group` file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  desc  'rationale', "
    The `/etc/group` file contains a list of all the valid groups defined in the system. The command below allows read/write access for root and read access for everyone else.

    The `/etc/group` file needs to be protected from unauthorized changes by non-privileged users, but needs to be readable as this information is used with many non-privileged programs.
  "
  desc  'check', "
    Run the following command to verify `/etc/group` is mode 644 or more restrictive, `Uid` is `0/root` and `Gid` is `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/group

    Access: (0644/-rw-r--r--)  Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to remove excess permissions, set owner, and set group on `/etc/group`:

    ```
    # chmod u-x,go-wx /etc/group
    # chown root:root /etc/group
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.3'
  tag cis_number:            '7.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure permissions on /etc/group are configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070103r1_rule.'
  end
end
