# encoding: UTF-8

control 'C-6.3.2.4' do
  title 'Ensure system warns when audit logs are low on space'
  desc  "
    The `auditd` daemon can be configured to halt the system, put the system in single user mode or send a warning message, if the partition that holds the audit log files is low on space.

    The `space_left_action` parameter tells the system what action to take when the system has detected that it is starting to get low on disk space. Valid values are `ignore`, `syslog`, `rotate`, `email`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon does nothing
    - `syslog`, the audit daemon will issue a warning to syslog
    - `rotate`, the audit daemon will rotate logs, losing the oldest to free up space
    - `email`, the audit daemon will send a warning to the email account specified in `action_mail_acct` as well as sending the message to syslog
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script. The script is also responsible for telling the auditd daemon to resume logging once its completed its action
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    The `admin_space_left_action` parameter tells the system what action to take when the system has detected that it is  low on disk space. Valid values are `ignore`, `syslog`, `rotate`, `email`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon does nothing
    - `syslog`, the audit daemon will issue a warning to syslog
    - `rotate`, the audit daemon will rotate logs, losing the oldest to free up space
    - `email`, the audit daemon will send a warning to the email account specified in `action_mail_acct` as well as sending the message to syslog
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script. The script is also responsible for telling the auditd daemon to resume logging once its completed its action
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability.
  "
  desc  'rationale', "
    The `auditd` daemon can be configured to halt the system, put the system in single user mode or send a warning message, if the partition that holds the audit log files is low on space.

    The `space_left_action` parameter tells the system what action to take when the system has detected that it is starting to get low on disk space. Valid values are `ignore`, `syslog`, `rotate`, `email`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon does nothing
    - `syslog`, the audit daemon will issue a warning to syslog
    - `rotate`, the audit daemon will rotate logs, losing the oldest to free up space
    - `email`, the audit daemon will send a warning to the email account specified in `action_mail_acct` as well as sending the message to syslog
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script. The script is also responsible for telling the auditd daemon to resume logging once its completed its action
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    The `admin_space_left_action` parameter tells the system what action to take when the system has detected that it is  low on disk space. Valid values are `ignore`, `syslog`, `rotate`, `email`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon does nothing
    - `syslog`, the audit daemon will issue a warning to syslog
    - `rotate`, the audit daemon will rotate logs, losing the oldest to free up space
    - `email`, the audit daemon will send a warning to the email account specified in `action_mail_acct` as well as sending the message to syslog
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script. The script is also responsible for telling the auditd daemon to resume logging once its completed its action
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability.
  "
  desc  'check', "
    Run the following command and verify the `space_left_action` is set to `email`, `exec`, `single`, or `halt`:

    ```
    grep -P -- '^\\h*space_left_action\\h*=\\h*(email|exec|single|halt)\\b' /etc/audit/auditd.conf
    ```

    Verify the output is `email`, `exec`, `single`, or `halt`

    _Example output_

    ```
    space_left_action = email
    ```

    Run the following command and verify the `admin_space_left_action` is set to `single` - OR - `halt`:

    ```
    grep -P -- '^\\h*admin_space_left_action\\h*=\\h*(single|halt)\\b' /etc/audit/auditd.conf
    ```

    Verify the output is `single` or `halt`

    _Example output:_

    ```
    admin_space_left_action = single
    ```

    Note: A Mail Transfer Agent (MTA) must be installed and configured properly to set `space_left_action = email`
  "
  desc  'fix', "
    Set the `space_left_action` parameter in `/etc/audit/auditd.conf` to `email`, `exec`, `single`, or `halt`:

    _Example:_

    ```
    space_left_action = email
    ```

    Set the `admin_space_left_action` parameter in `/etc/audit/auditd.conf` to `single` or `halt`:

    _Example:_

    ```
    admin_space_left_action = single
    ```

    Note: A Mail Transfer Agent (MTA) must be installed and configured properly to set `space_left_action = email`
  "
  tag severity:              'medium'
  tag nist:                  ['AU-2 a', 'AU-4']
  tag cci:                   ['CCI-000123', 'CCI-001848']
  tag cis_rid:               '6.3.2.4'
  tag cis_number:            '6.3.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -E '^\s*space_left_action\s*=\s*(email|exec|single|halt)' /etc/audit/auditd.conf}) do
    its('stdout') { should match(/\S/) }
  end
end