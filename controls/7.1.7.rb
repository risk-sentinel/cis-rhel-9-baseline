# encoding: UTF-8

control 'C-7.1.7' do
  title 'Ensure permissions on /etc/gshadow are configured'
  desc  "
    The `/etc/gshadow` file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.

    If attackers can gain read access to the `/etc/gshadow` file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the `/etc/gshadow` file (such as group administrators) could also be useful to subvert the group.
  "
  desc  'rationale', "
    The `/etc/gshadow` file is used to store the information about groups that is critical to the security of those accounts, such as the hashed password and other security information.

    If attackers can gain read access to the `/etc/gshadow` file, they can easily run a password cracking program against the hashed password to break it. Other security information that is stored in the `/etc/gshadow` file (such as group administrators) could also be useful to subvert the group.
  "
  desc  'check', "
    Run the following command to verify `/etc/gshadow` is mode 000, `Uid` is `0/root` and `Gid` is `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)'  /etc/gshadow

    Access: (0/----------)  Uid: ( 0/ root) Gid: ( 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to set mode, owner, and group on `/etc/gshadow`:

    ```
    # chown root:root /etc/gshadow
    # chmod 0000 /etc/gshadow
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'CM-8 a 1']
  tag cci:                   ['CCI-000213', 'CCI-000389']
  tag cis_rid:               '7.1.7'
  tag cis_number:            '7.1.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070107r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure permissions on /etc/gshadow are configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070107r1_rule.'
  end
end
