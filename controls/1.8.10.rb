# encoding: UTF-8

control 'C-1.8.10' do
  title 'Ensure XDMCP is not enabled'
  desc  "
    X Display Manager Control Protocol (XDMCP) is designed to provide authenticated access to display management services for remote displays

    XDMCP is inherently insecure.
    - XDMCP is not a ciphered protocol. This may allow an attacker to capture keystrokes entered by a user
    - XDMCP is vulnerable to man-in-the-middle attacks. This may allow an attacker to steal the credentials of legitimate users by impersonating the XDMCP server.
  "
  desc  'rationale', "
    X Display Manager Control Protocol (XDMCP) is designed to provide authenticated access to display management services for remote displays

    XDMCP is inherently insecure.
    - XDMCP is not a ciphered protocol. This may allow an attacker to capture keystrokes entered by a user
    - XDMCP is vulnerable to man-in-the-middle attacks. This may allow an attacker to steal the credentials of legitimate users by impersonating the XDMCP server.
  "
  desc  'check', "
    Run the following command and verify the output:

    ```
    # grep -Eis '^\\s*Enable\\s*=\\s*true' /etc/gdm/custom.conf

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Edit the file `/etc/gdm/custom.conf` and remove the line:

    ```
    Enable=true
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.8.10'
  tag cis_number:            '1.8.10'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010810r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure XDMCP is not enabled' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-010810r1_rule.'
  end
end
