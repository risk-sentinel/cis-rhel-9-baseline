# encoding: UTF-8

control 'C-6.2.3.7' do
  title 'Ensure rsyslog is not configured to receive logs from a remote client'
  desc  "
    `rsyslog` supports the ability to receive messages from remote hosts, thus acting as a log server. Clients should not receive data from other hosts.

    If a client is configured to also receive data, thus turning it into a server, the client system is acting outside its operational boundary.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'rationale', "
    `rsyslog` supports the ability to receive messages from remote hosts, thus acting as a log server. Clients should not receive data from other hosts.

    If a client is configured to also receive data, thus turning it into a server, the client system is acting outside its operational boundary.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'check', "
    Review the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files and verify that the system is not configured to accept incoming logs.

    advanced format

    ```
    # grep -Psi -- '^\\h*module\\(load=\\\"?imtcp\\\"?\\)' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    # grep -Psi -- '^\\h*input\\(type=\\\"?imtcp\\\"?\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    ```

    Nothing should be returned


    obsolete legacy format

    ```
    # grep -Psi -- '^\\h*\\$ModLoad\\h+imtcp\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    # grep -Psi -- '^\\h*\\$InputTCPServerRun\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Should there be any active log server configuration found in the auditing section, modify those files and remove the specific lines highlighted by the audit. Verify none of the following entries are present in any of `/etc/rsyslog.conf` or `/etc/rsyslog.d/*.conf`.

    advanced format

    ```
    module(load=\"imtcp\")
    input(type=\"imtcp\" port=\"514\")
    ```

    deprecated legacy format

    ```
    $ModLoad imtcp
    $InputTCPServerRun
    ```

    Restart the service:

    ```
    # systemctl restart rsyslog
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '6.2.3.7'
  tag cis_number:            '6.2.3.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020307r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE '^\s*(module\(load="im(tcp|udp|relp)"|\$ModLoad\s+im(tcp|udp|relp)|input\(type="im(tcp|udp|relp)"|\$InputTCPServerRun|\$InputUDPServerRun)' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null}) do
    its('stdout.strip') { should be_empty }
  end
end