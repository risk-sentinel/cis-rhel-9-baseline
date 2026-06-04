# encoding: UTF-8

control 'C-6.2.2.1.1' do
  title 'Ensure systemd-journal-remote is installed'
  desc  "
    Journald `systemd-journal-remote` supports the ability to send log events it gathers to a remote log host or to receive messages from remote hosts, thus enabling centralized log management.

    Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'rationale', "
    Journald `systemd-journal-remote` supports the ability to send log events it gathers to a remote log host or to receive messages from remote hosts, thus enabling centralized log management.

    Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'check', "
    - IF - `journald` will be used for logging on the system:

    Run the following command to verify `systemd-journal-remote` is installed.

    ```
    # rpm -q systemd-journal-remote
    ```

    Verify the output matches:

    ```
    systemd-journal-remote- ```
  "
  desc  'fix', "
    Run the following command to install `systemd-journal-remote`:

    ```
    # dnf install systemd-journal-remote
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.2.1.1'
  tag cis_number:            '6.2.2.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0602020101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  impact 0.5
  describe 'systemd-journal-remote installed (6.2.2.1.1)' do
    skip 'operational: remote-log forwarding is a site-specific architecture choice; applicable only when central journald collection is used.'
  end
end