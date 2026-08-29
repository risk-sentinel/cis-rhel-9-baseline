# encoding: UTF-8

control 'C-7.1.10' do
  title 'Ensure permissions on /etc/security/opasswd are configured'
  desc  "
    `/etc/security/opasswd` and it's backup `/etc/security/opasswd.old` hold user's previous passwords if `pam_unix` or `pam_pwhistory` is in use on the system

    It is critical to ensure that `/etc/security/opasswd` is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'rationale', "
    `/etc/security/opasswd` and it's backup `/etc/security/opasswd.old` hold user's previous passwords if `pam_unix` or `pam_pwhistory` is in use on the system

    It is critical to ensure that `/etc/security/opasswd` is protected from unauthorized access. Although it is protected by default, the file permissions could be changed either inadvertently or through malicious actions.
  "
  desc  'check', "
    Run the following commands to verify `/etc/security/opasswd` and `/etc/security/opasswd.old` are mode 600 or more restrictive, `Uid` is `0/root` and `Gid` is `0/root` if they exist:

    ```
    #  [ -e \"/etc/security/opasswd\" ] && stat -Lc '%n Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/security/opasswd

    /etc/security/opasswd Access: (0600/-rw-------)  Uid: ( 0/ root) Gid: ( 0/ root)
     -OR-
    Nothing is returned
    ```

    ```
    #  [ -e \"/etc/security/opasswd.old\" ] && stat -Lc '%n Access: (%#a/%A)  Uid: ( %u/ %U) Gid: ( %g/ %G)' /etc/security/opasswd.old

    /etc/security/opasswd.old Access: (0600/-rw-------)  Uid: ( 0/ root) Gid: ( 0/ root)
     -OR-
    Nothing is returned
    ```
  "
  desc  'fix', "
    Run the following commands to remove excess permissions, set owner, and set group on `/etc/security/opasswd` and `/etc/security/opasswd.old` is they exist:

    ```
    # [ -e \"/etc/security/opasswd\" ] && chmod u-x,go-rwx /etc/security/opasswd
    # [ -e \"/etc/security/opasswd\" ] && chown root:root /etc/security/opasswd
    # [ -e \"/etc/security/opasswd.old\" ] && chmod u-x,go-rwx /etc/security/opasswd.old
    # [ -e \"/etc/security/opasswd.old\" ] && chown root:root /etc/security/opasswd.old
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '7.1.10'
  tag cis_number:            '7.1.10'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070110r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe file('/etc/security/opasswd') do
    it { should exist }
    it { should_not be_more_permissive_than('0600') }
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
end