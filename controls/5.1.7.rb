# encoding: UTF-8

control 'C-5.1.7' do
  title 'Ensure sshd access is configured'
  desc  "
    There are several options available to limit which users and group can access the system via SSH. It is recommended that at least one of the following options be leveraged:

    - `AllowUsers`:
      - The `AllowUsers` variable gives the system administrator the option of allowing specific users to `ssh` into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.
    - `AllowGroups`:
      - The `AllowGroups` variable gives the system administrator the option of allowing specific groups of users to `ssh` into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.
    - `DenyUsers`:
      - The `DenyUsers` variable gives the system administrator the option of denying specific users to `ssh` into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.
    - `DenyGroups`:
      - The `DenyGroups` variable gives the system administrator the option of denying specific groups of users to `ssh` into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.

    Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.
  "
  desc  'rationale', "
    There are several options available to limit which users and group can access the system via SSH. It is recommended that at least one of the following options be leveraged:

    - `AllowUsers`:
      - The `AllowUsers` variable gives the system administrator the option of allowing specific users to `ssh` into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by only allowing the allowed users to log in from a particular host, the entry can be specified in the form of user@host.
    - `AllowGroups`:
      - The `AllowGroups` variable gives the system administrator the option of allowing specific groups of users to `ssh` into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.
    - `DenyUsers`:
      - The `DenyUsers` variable gives the system administrator the option of denying specific users to `ssh` into the system. The list consists of space separated user names. Numeric user IDs are not recognized with this variable. If a system administrator wants to restrict user access further by specifically denying a user's access from a particular host, the entry can be specified in the form of user@host.
    - `DenyGroups`:
      - The `DenyGroups` variable gives the system administrator the option of denying specific groups of users to `ssh` into the system. The list consists of space separated group names. Numeric group IDs are not recognized with this variable.

    Restricting which users can remotely access the system via SSH will help ensure that only authorized users access the system.
  "
  desc  'check', "
    Run the following command and verify the output:

    ```
    # sshd -T | grep -Pi -- '^\\h*(allow|deny)(users|groups)\\h+\\H+'
    ```

    Verify that the output matches at least one of the following lines:

    ```
    allowusers -OR-
    allowgroups -OR-
    denyusers -OR-
    denygroups ```

    Review the list(s) to ensure included users and/or groups follow local site policy

    - IF - `Match` set statements are used in your environment, specify the connection parameters to use for the `-T` extended test mode and run the audit to verify the setting is not incorrectly configured in a match block

    _Example additional audit needed for a match block for the user `sshuser`:_

    ```
    # sshd -T -C user=sshuser | grep -Pi -- '^\\h*(allow|deny)(users|groups)\\h+\\H+'
    ```

    Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple `-C` options or as a comma-separated list. The keywords are `addr` (source address), `user` (user), `host` (resolved source host name), `laddr` (local address), `lport` (local port number), and `rdomain` (routing domain).
  "
  desc  'fix', "
    Edit the `/etc/ssh/sshd_config` file to set one or more of the parameters above any `Include` and `Match` set statements as follows:

    ```
    AllowUsers - AND/OR -
    AllowGroups ```

    Note: 
    - First occurrence of a option takes precedence, `Match` set statements withstanding. If `Include` locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a `.conf` file in a `Include` directory.
    - Be advised that these options are \"ANDed\" together. If both `AllowUsers` and `AllowGroups` are set, connections will be limited to the list of users that are also a member of an allowed group. It is recommended that only one be set for clarity and ease of administration.
    - It is easier to manage an allow list than a deny list. In a deny list, you could potentially add a user or group and forget to add it to the deny list.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-11 b']
  tag cci:                   ['CCI-000213', 'CCI-000056']
  tag cis_rid:               '5.1.7'
  tag cis_number:            '5.1.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050107r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'policy'

  impact 0.5
  describe 'sshd access control (5.1.7)' do
    skip 'manual/policy: the AllowUsers/AllowGroups/DenyUsers/DenyGroups access map is consumer-policy-specific. Operator attests the configured access directives against their access policy.'
  end
end