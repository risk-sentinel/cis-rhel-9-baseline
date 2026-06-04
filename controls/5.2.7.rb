# encoding: UTF-8

control 'C-5.2.7' do
  title 'Ensure access to the su command is restricted'
  desc  "
    The `su` command allows a user to run a command or shell as another user. The program has been superseded by `sudo`, which allows for more granular control over privileged access. Normally, the `su` command can be executed by any user. By uncommenting the `pam_wheel.so` statement in `/etc/pam.d/su`, the `su` command will only allow users in a specific groups to execute `su`. This group should be empty to reinforce the use of `sudo` for privileged access.

    Restricting the use of `su` , and using `sudo` in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via `sudo` , whereas `su` can only record that a user executed the `su` program.
  "
  desc  'rationale', "
    The `su` command allows a user to run a command or shell as another user. The program has been superseded by `sudo`, which allows for more granular control over privileged access. Normally, the `su` command can be executed by any user. By uncommenting the `pam_wheel.so` statement in `/etc/pam.d/su`, the `su` command will only allow users in a specific groups to execute `su`. This group should be empty to reinforce the use of `sudo` for privileged access.

    Restricting the use of `su` , and using `sudo` in its place, provides system administrators better control of the escalation of user privileges to execute privileged commands. The sudo utility also provides a better logging and audit mechanism, as it can log each command executed via `sudo` , whereas `su` can only record that a user executed the `su` program.
  "
  desc  'check', "
    Run the following command and verify the output matches the line:
    ```
    # grep -Pi '^\\h*auth\\h+(?:required|requisite)\\h+pam_wheel\\.so\\h+(?:[^#\\n\\r]+\\h+)?((?!\\2)(use_uid\\b|group=\\H+\\b))\\h+(?:[^#\\n\\r]+\\h+)?((?!\\1)(use_uid\\b|group=\\H+\\b))(\\h+.*)?$' /etc/pam.d/su

    auth required pam_wheel.so use_uid group= ```

    Run the following command and verify that the group specified in ` ` contains no users:
    ```
    # grep /etc/group :x: :
    ```
    There should be no users listed after the Group ID field.
  "
  desc  'fix', "
    Create an empty group that will be specified for use of the `su` command.  The group should be named according to site policy.

    _Example:_
    ```
    # groupadd sugroup
    ```

    Add the following line to the `/etc/pam.d/su` file, specifying the empty group:
    ```
    auth required pam_wheel.so use_uid group=sugroup
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-2 a']
  tag cci:                   ['CCI-000213', 'CCI-002110']
  tag cis_rid:               '5.2.7'
  tag cis_number:            '5.2.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050207r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -Pi -- '^\h*auth\h+(required|requisite)\h+pam_wheel\.so\h+([^#\n\r]+\h+)?(use_uid\h+)?([^#\n\r]+\h+)?group=' /etc/pam.d/su 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end