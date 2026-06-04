# encoding: UTF-8

control 'C-1.6.3' do
  title 'Ensure system wide crypto policy disables sha1 hash and signature support'
  desc  "
    SHA-1 (Secure Hash Algorithm) is a cryptographic hash function that produces a 160 bit hash value.

    The SHA-1 hash function has an inherently weak design, and advancing cryptanalysis has made it vulnerable to attacks. The most significant danger for a hash algorithm is when a \"collision\" which happens when two different pieces of data produce the same hash value occurs. This hashing algorithm has been considered weak since 2005.

    Note: The use of SHA-1 with hashbased message authentication codes (HMAC) do not rely on the collision resistance of the corresponding hash function, and therefore the recent attacks on SHA-1 have a significantly lower impact on the use of SHA-1 for HMAC. Because of this, the recommendation does not disable the hmac-sha1 MAC.
  "
  desc  'rationale', "
    SHA-1 (Secure Hash Algorithm) is a cryptographic hash function that produces a 160 bit hash value.

    The SHA-1 hash function has an inherently weak design, and advancing cryptanalysis has made it vulnerable to attacks. The most significant danger for a hash algorithm is when a \"collision\" which happens when two different pieces of data produce the same hash value occurs. This hashing algorithm has been considered weak since 2005.

    Note: The use of SHA-1 with hashbased message authentication codes (HMAC) do not rely on the collision resistance of the corresponding hash function, and therefore the recent attacks on SHA-1 have a significantly lower impact on the use of SHA-1 for HMAC. Because of this, the recommendation does not disable the hmac-sha1 MAC.
  "
  desc  'check', "
    Run the following commands to verify `SHA1` hash and signature support has been disabled:

    Run the following command to verify that the `hash` and `sign` lines do not include the `SHA1` hash:

    ```
    # awk -F= '($1~/(hash|sign)/ && $2~/SHA1/ && $2!~/^\\s*\\-\\s*([^#\\n\\r]+)?SHA1/){print}' /etc/crypto-policies/state/CURRENT.pol
    ```

    Nothing should be returned

    Run the following command to verify that `sha1_in_certs` is set to `0` (disabled):

    ```
    # grep -Psi -- '^\\h*sha1_in_certs\\h*=\\h*' /etc/crypto-policies/state/CURRENT.pol

    sha1_in_certs = 0
    ```
  "
  desc  'fix', "
    Note: 
    - The commands below are written for the included `DEFAULT` system-wide crypto policy. If another policy is in use and follows local site policy, replace `DEFAULT` with the name of your system-wide crypto policy.
    - Multiple subpolicies may be assigned to a policy as a colon separated list. e.g. `DEFAULT:NO-SHA1:NO-SSHCBC`
    - Subpolicies:
      - Not included in the `update-crypto-policies --set` command will not be applied to the system wide crypto policy.
      - must exist before they can be applied to the system wide crypto policy.
      -  `.pmod` file filenames must be in all upper case, upper case, e.g. `NO-SHA1.pmod`, or they will not be read by the `update-crypto-policies  --set` command.

    Create or edit a file in `/etc/crypto-policies/policies/modules/` ending in `.pmod` and add or modify the following lines:

    ```
    hash = -SHA1
    sign = -*-SHA1
    sha1_in_certs = 0
    ```

    _Example:_

    ```
    # printf '%s\\n' \"# This is a subpolicy dropping the SHA1 hash and signature support\" \"hash = -SHA1\" \"sign = -*-SHA1\" \"sha1_in_certs = 0\" >> /etc/crypto-policies/policies/modules/NO-SHA1.pmod
    ```

    Run the following command to update the system-wide cryptographic policy

    ```
    # update-crypto-policies --set : : : ```

    _Example:_

    ```
    update-crypto-policies --set DEFAULT:NO-SHA1
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
  tag cis_rid:               '1.6.3'
  tag cis_number:            '1.6.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010603r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{awk -F= '($1~/(hash|sign)/ && $2~/SHA1/ && $2!~/^\s*\-\s*([^#\n\r]+)?SHA1/){print}' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
  describe command(%q{grep -Psi -- '^\h*sha1_in_certs\h*=\h*' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null}) do
    its('stdout') { should match(/=\s*0/) }
  end
end