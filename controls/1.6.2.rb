# encoding: UTF-8

control 'C-1.6.2' do
  title 'Ensure system wide crypto policy is not set in sshd configuration'
  desc  "
    System-wide Crypto policy can be over-ridden or opted out of for openSSH

    Over-riding or opting out of the system-wide crypto policy could allow for the use of less secure Ciphers, MACs, KexAlgorithms and GSSAPIKexAlgorithm

    Note: If changes to the system-wide crypto policy are required to meet local site policy for the openSSH server, these changes should be done with a `sub-policy` assigned to the system-wide crypto policy. For additional information see the CRYPTO-POLICIES(7) man page
  "
  desc  'rationale', "
    System-wide Crypto policy can be over-ridden or opted out of for openSSH

    Over-riding or opting out of the system-wide crypto policy could allow for the use of less secure Ciphers, MACs, KexAlgorithms and GSSAPIKexAlgorithm

    Note: If changes to the system-wide crypto policy are required to meet local site policy for the openSSH server, these changes should be done with a `sub-policy` assigned to the system-wide crypto policy. For additional information see the CRYPTO-POLICIES(7) man page
  "
  desc  'check', "
    Run the following command:

    ```
    # grep -Pi '^\\h*CRYPTO_POLICY\\h*=' /etc/sysconfig/sshd
    ```

    No output should be returned
  "
  desc  'fix', "
    Run the following commands:

    ```
    # sed -ri \"s/^\\s*(CRYPTO_POLICY\\s*=.*)$/# \\1/\" /etc/sysconfig/sshd

    # systemctl reload sshd
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_rid:               '1.6.2'
  tag cis_number:            '1.6.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010602r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure system wide crypto policy is not set in sshd configuration' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-010602r1_rule.'
  end
end
