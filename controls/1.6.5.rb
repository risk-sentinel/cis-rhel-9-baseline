# encoding: UTF-8

control 'C-1.6.5' do
  title 'Ensure system wide crypto policy disables cbc for ssh'
  desc  "
    Cypher Block Chaining (CBC) is an algorithm that uses a block cipher.

    A vulnerability exists in SSH messages that employ CBC mode that may allow an attacker to recover plaintext from a block of ciphertext. If exploited, this attack can potentially allow an attacker to recover up to 32 bits of plaintext from an arbitrary block of ciphertext from a connection secured using the SSH protocol.
  "
  desc  'rationale', "
    Cypher Block Chaining (CBC) is an algorithm that uses a block cipher.

    A vulnerability exists in SSH messages that employ CBC mode that may allow an attacker to recover plaintext from a block of ciphertext. If exploited, this attack can potentially allow an attacker to recover up to 32 bits of plaintext from an arbitrary block of ciphertext from a connection secured using the SSH protocol.
  "
  desc  'check', "
    Run the following script to verify `CBC` is disabled for `SSH`:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\"
       if grep -Piq -- '^\\h*cipher\\h*=\\h*([^#\\n\\r]+)?-CBC\\b' /etc/crypto-policies/state/CURRENT.pol; then
          if grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*' /etc/crypto-policies/state/CURRENT.pol; then
             if ! grep -Piq -- '^\\h*cipher@(lib|open)ssh(-server|-client)?\\h*=\\h*([^#\\n\\r]+)?-CBC\\b' /etc/crypto-policies/state/CURRENT.pol; then
                l_output=\"$l_output\\n - Cipher Block Chaining (CBC) is disabled for SSH\"
             else
                l_output2=\"$l_output2\\n - Cipher Block Chaining (CBC) is enabled for SSH\"
             fi
          else
             l_output2=\"$l_output2\\n - Cipher Block Chaining (CBC) is enabled for SSH\"
          fi
       else
          l_output=\" - Cipher Block Chaining (CBC) is disabled\"
       fi
       if [ -z \"$l_output2\" ]; then # Provide output from checks
          echo -e \"\\n- Audit Result:\\n   PASS \\n$l_output\\n\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\\n\"
          [ -n \"$l_output\" ] && echo -e \"\\n- Correctly set:\\n$l_output\\n\"
       fi
    }
    ```
  "
  desc  'fix', "
    Note: 
    - The commands below are written for the included `DEFAULT` system-wide crypto policy. If another policy is in use and follows local site policy, replace `DEFAULT` with the name of your system-wide crypto policy.
    - `CBC` can be turned off globally by using the argument `cipher` opposed to `cipher@SSH`
    - Multiple subpolicies may be assigned to a policy as a colon separated list. e.g. `DEFAULT:NO-SHA1:NO-SSHCBC`
    - Subpolicies:
      - Not included in the `update-crypto-policies --set` command will not be applied to the system wide crypto policy.
      - must exist before they can be applied to the system wide crypto policy.
      -  `.pmod` file filenames must be in all upper case, upper case, e.g. `NO-SSHCBC.pmod`, or they will not be read by the `update-crypto-policies  --set` command.
    Create or edit a file in `/etc/crypto-policies/policies/modules/` ending in `.pmod` and add or modify one of the the following lines:

    ```
    cipher@SSH = -*-CBC # Disables the CBC cipher for SSH
    ```

    _Example:_

    ```
    # printf '%s\\n' \"# This is a subpolicy to disable all CBC mode ciphers\" \"# for the SSH protocol (libssh and OpenSSH)\" \"cipher@SSH = -*-CBC\" >> /etc/crypto-policies/policies/modules/NO-SSHCBC.pmod
    ```

    Run the following command to update the system-wide cryptographic policy

    ```
    # update-crypto-policies --set : : : ```

    _Example:_

    ```
    update-crypto-policies --set DEFAULT:NO-SHA1:NO-WEAKMAC:NO-SSHCBC
    ```

    Run the following command to reboot the system to make your cryptographic settings effective for already running services and applications:

    ```
    # reboot
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-8', 'AC-8 a']
  tag cci:                   ['CCI-002418', 'CCI-000051']
  tag cis_rid:               '1.6.5'
  tag cis_number:            '1.6.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010605r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -Pi -- '^\h*cipher@(lib|open)ssh(-server|-client)?\h*=\h*([^#\n\r]+)?-CBC\b' /etc/crypto-policies/state/CURRENT.pol 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end