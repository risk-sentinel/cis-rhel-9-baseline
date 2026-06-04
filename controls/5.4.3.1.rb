# encoding: UTF-8

control 'C-5.4.3.1' do
  title 'Ensure nologin is not listed in /etc/shells'
  desc  "
    `/etc/shells` is a text file which contains the full pathnames of valid login shells. This file is consulted by `chsh` and available to be queried by other programs.

    Be aware that there are programs which consult this file to find out if a user is a normal user; for example, FTP daemons traditionally disallow access to users with shells not included in this file.

    A user can use `chsh` to change their configured shell.

    If a user has a shell configured that isn't in in `/etc/shells`, then the system assumes that they're somehow restricted. In the case of `chsh` it means that the user cannot change that value.

    Other programs might query that list and apply similar restrictions.

    By putting `nologin` in `/etc/shells`, any user that has `nologin` as its shell is considered a full, unrestricted user. This is not the expected behavior for `nologin`.
  "
  desc  'rationale', "
    `/etc/shells` is a text file which contains the full pathnames of valid login shells. This file is consulted by `chsh` and available to be queried by other programs.

    Be aware that there are programs which consult this file to find out if a user is a normal user; for example, FTP daemons traditionally disallow access to users with shells not included in this file.

    A user can use `chsh` to change their configured shell.

    If a user has a shell configured that isn't in in `/etc/shells`, then the system assumes that they're somehow restricted. In the case of `chsh` it means that the user cannot change that value.

    Other programs might query that list and apply similar restrictions.

    By putting `nologin` in `/etc/shells`, any user that has `nologin` as its shell is considered a full, unrestricted user. This is not the expected behavior for `nologin`.
  "
  desc  'check', "
    Run the following command to verify that `nologin` is not listed in the `/etc/shells` file:

    ```
    # grep -Ps '^\\h*([^#\\n\\r]+)?\\/nologin\\b' /etc/shells
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Edit `/etc/shells` and remove any lines that include `nologin`
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.4.3.1'
  tag cis_number:            '5.4.3.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040301r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure nologin is not listed in /etc/shells' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-05040301r1_rule.'
  end
end
