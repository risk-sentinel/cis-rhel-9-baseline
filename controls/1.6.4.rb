# encoding: UTF-8

control 'C-1.6.4' do
  title 'Ensure system wide crypto policy disables macs less than 128 bits'
  desc  "
    Message Authentication Code (MAC) algorithm is a family of cryptographic functions that is parameterized by a symmetric key. Each of the functions can act on input data (called a \"message\") of variable length to produce an output value of a specified length. The output value is called the MAC of the input message.

    A MAC algorithm can be used to provide data-origin authentication and data-integrity protection

    Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the tunnel and capture credentials and information.

    A MAC algorithm must be computationally infeasible to determine the MAC of a message without knowledge of the key, even if one has already seen the results of using that key to compute the MAC's of other messages.
  "
  desc  'rationale', "
    Message Authentication Code (MAC) algorithm is a family of cryptographic functions that is parameterized by a symmetric key. Each of the functions can act on input data (called a \"message\") of variable length to produce an output value of a specified length. The output value is called the MAC of the input message.

    A MAC algorithm can be used to provide data-origin authentication and data-integrity protection

    Weak algorithms continue to have a great deal of attention as a weak spot that can be exploited with expanded computing power. An attacker that breaks the algorithm could take advantage of a MiTM position to decrypt the tunnel and capture credentials and information.

    A MAC algorithm must be computationally infeasible to determine the MAC of a message without knowledge of the key, even if one has already seen the results of using that key to compute the MAC's of other messages.
  "
  desc  'check', "
    Run the following script to verify weak MACs are disabled:

    ```
    # grep -Pi -- '^\\h*mac\\h*=\\h*([^#\\n\\r]+)?-64\\b' /etc/crypto-policies/state/CURRENT.pol

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Note: 
    - The commands below are written for the included `DEFAULT` system-wide crypto policy. If another policy is in use and follows local site policy, replace `DEFAULT` with the name of your system-wide crypto policy.
    - Multiple subpolicies may be assigned to a policy as a colon separated list. e.g. `DEFAULT:NO-SHA1:NO-SSHCBC`
    - Subpolicies:
      - Not included in the `update-crypto-policies --set` command will not be applied to the system wide crypto policy.
      - must exist before they can be applied to the system wide crypto policy.
      -  `.pmod` file filenames must be in all upper case, upper case, e.g. `NO-WEAKMAC.pmod`, or they will not be read by the `update-crypto-policies  --set` command.

    Create or edit a file in `/etc/crypto-policies/policies/modules/` ending in `.pmod` and add or modify one of the following lines:

    ```
    mac = -*-64* # Disables weak macs
    ```

    _Example:_

    ```
    # printf '%s\\n' \"# This is a subpolicy to disable weak macs\" \"mac = -*-64\" >> /etc/crypto-policies/policies/modules/NO-WEAKMAC.pmod
    ```

    Run the following command to update the system-wide cryptographic policy

    ```
    # update-crypto-policies --set : : : ```

    _Example:_

    ```
    update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC
    ```

    Run the following command to reboot the system to make your cryptographic settings effective for already running services and applications:

    ```
    # reboot
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_rid:               '1.6.4'
  tag cis_number:            '1.6.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010604r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -Pi -- '^\h*mac\h*=\h*([^#\n\r]+)?-64\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end