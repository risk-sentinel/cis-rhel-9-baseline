# encoding: UTF-8

control 'C-5.1.21' do
  title 'Ensure sshd PermitUserEnvironment is disabled'
  desc  "
    The `PermitUserEnvironment` option allows users to present environment options to the SSH daemon.

    Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has SSH executing trojan'd programs)
  "
  desc  'rationale', "
    The `PermitUserEnvironment` option allows users to present environment options to the SSH daemon.

    Permitting users the ability to set environment variables through the SSH daemon could potentially allow users to bypass security controls (e.g. setting an execution path that has SSH executing trojan'd programs)
  "
  desc  'check', "
    Run the following command to verify `PermitUserEnviroment` is set to `no`:

    ```
    # sshd -T | grep permituserenvironment

    permituserenvironment no
    ```
  "
  desc  'fix', "
    Edit the `/etc/ssh/sshd_config` file to set the `PermitUserEnvironment` parameter to `no` above any `Include` entries as follows:

    ```
    PermitUserEnvironment no
    ```

    Note: First occurrence of an option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.1.21'
  tag cis_number:            '5.1.21'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050121r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe sshd_config do
    its('PermitUserEnvironment') { should cmp 'no' }
  end
end