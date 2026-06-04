# encoding: UTF-8

control 'C-5.1.19' do
  title 'Ensure sshd PermitEmptyPasswords is disabled'
  desc  "
    The `PermitEmptyPasswords` parameter specifies if the SSH server allows login to accounts with empty password strings.

    Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system.
  "
  desc  'rationale', "
    The `PermitEmptyPasswords` parameter specifies if the SSH server allows login to accounts with empty password strings.

    Disallowing remote shell access to accounts that have an empty password reduces the probability of unauthorized access to the system.
  "
  desc  'check', "
    Run the following command to verify `PermitEmptyPasswords` is set to `no`:

    ```
    # sshd -T | grep permitemptypasswords

    permitemptypasswords no
    ```

    - IF - `Match` set statements are used in your environment, specify the connection parameters to use for the `-T` extended test mode and run the audit to verify the setting is not incorrectly configured in a match block

    _Example additional audit needed for a match block for the user `sshuser`:_

    ```
    # sshd -T -C user=sshuser | grep permitemptypasswords
    ```

    Note: If provided, any Match directives in the configuration file that would apply are applied before the configuration is written to standard output. The connection parameters are supplied as keyword=value pairs and may be supplied in any order, either with multiple `-C` options or as a comma-separated list. The keywords are `addr` (source address), `user` (user), `host` (resolved source host name), `laddr` (local address), `lport` (local port number), and `rdomain` (routing domain)
  "
  desc  'fix', "
    Edit `/etc/ssh/sshd_config` and set the `PermitEmptyPasswords` parameter to `no` above any `Include` and `Match` entries as follows:

    ```
    PermitEmptyPasswords no
    ```

    Note: First occurrence of an option takes precedence, `Match` set statements withstanding. If `Include` locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in `Include` location.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.1.19'
  tag cis_number:            '5.1.19'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050119r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe sshd_config do
    its('PermitEmptyPasswords') { should cmp 'no' }
  end
end