# encoding: UTF-8

control 'C-7.1.2' do
  title 'Ensure permissions on /etc/passwd- are configured'
  desc  "
    The `/etc/passwd-` file contains backup user account information.

    It is critical to ensure that the `/etc/passwd-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'rationale', "
    The `/etc/passwd-` file contains backup user account information.

    It is critical to ensure that the `/etc/passwd-` file is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'check', "
    Run the following command to verify `/etc/passwd-` is mode 644 or more restrictive, `Uid` is `0/root` and `Gid` is `0/root`:

    ```
    # stat -Lc 'Access: (%#a/%A)  Uid: ( %u/ %U) Gid: { %g/ %G)' /etc/passwd-

    Access: (0644/-rw-r--r--)  Uid: ( 0/ root) Gid: { 0/ root)
    ```
  "
  desc  'fix', "
    Run the following commands to remove excess permissions, set owner, and set group on `/etc/passwd-`:

    ```
    # chmod u-x,go-wx /etc/passwd-
    # chown root:root /etc/passwd-
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.2'
  tag cis_number:            '7.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure permissions on /etc/passwd- are configured' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-070102r1_rule.'
  end
end
