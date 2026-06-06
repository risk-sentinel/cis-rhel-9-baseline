# encoding: UTF-8

control 'C-1.6.1' do
  title 'Ensure system wide crypto policy is not set to legacy'
  desc  "
    When a system-wide policy is set up, the default behavior of applications will be to follow the policy. Applications will be unable to use algorithms and
    protocols that do not meet the policy, unless you explicitly request the application to do so.

    The system-wide crypto-policies followed by the crypto core components allow consistently deprecating and disabling algorithms system-wide.

    The `LEGACY` policy ensures maximum compatibility with version 5 of the operating system and earlier; it is less secure due to an increased attack surface. In addition to the `DEFAULT` level algorithms and protocols, it includes support for the `TLS 1.0` and `1.1` protocols. The algorithms `DSA`, `3DES`, and `RC4` are allowed, while `RSA keys` and `Diffie-Hellman` parameters are accepted if they are at least 1023 bits long.

    If the `LEGACY` system-wide crypto policy is selected, it includes support for TLS 1.0, TLS 1.1, and SSH2 protocols or later. The algorithms DSA, 3DES, and RC4 are allowed, while RSA and Diffie-Hellman parameters are accepted if larger than 1023-bits.

    These legacy protocols and algorithms can make the system vulnerable to attacks, including those listed in RFC 7457
  "
  desc  'rationale', "
    When a system-wide policy is set up, the default behavior of applications will be to follow the policy. Applications will be unable to use algorithms and
    protocols that do not meet the policy, unless you explicitly request the application to do so.

    The system-wide crypto-policies followed by the crypto core components allow consistently deprecating and disabling algorithms system-wide.

    The `LEGACY` policy ensures maximum compatibility with version 5 of the operating system and earlier; it is less secure due to an increased attack surface. In addition to the `DEFAULT` level algorithms and protocols, it includes support for the `TLS 1.0` and `1.1` protocols. The algorithms `DSA`, `3DES`, and `RC4` are allowed, while `RSA keys` and `Diffie-Hellman` parameters are accepted if they are at least 1023 bits long.

    If the `LEGACY` system-wide crypto policy is selected, it includes support for TLS 1.0, TLS 1.1, and SSH2 protocols or later. The algorithms DSA, 3DES, and RC4 are allowed, while RSA and Diffie-Hellman parameters are accepted if larger than 1023-bits.

    These legacy protocols and algorithms can make the system vulnerable to attacks, including those listed in RFC 7457
  "
  desc  'check', "
    Run the following command to verify that the system-wide crypto policy is not `LEGACY`

    ```
    # grep -Pi '^\\h*LEGACY\\b' /etc/crypto-policies/config
    ```

    Verify that no lines are returned
  "
  desc  'fix', "
    Run the following command to change the system-wide crypto policy

    ```
    # update-crypto-policies --set ```

    _Example:_

    ```
    # update-crypto-policies --set DEFAULT
    ```

    Run the following to make the updated system-wide crypto policy active

    ```
    # update-crypto-policies
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_rid:               '1.6.1'
  tag cis_number:            '1.6.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010601r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{update-crypto-policies --show 2>/dev/null}) do
    its('stdout') { should_not match(/LEGACY/) }
  end
end