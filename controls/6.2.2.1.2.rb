# encoding: UTF-8

control 'C-6.2.2.1.2' do
  title 'Ensure systemd-journal-upload authentication is configured'
  desc  "
    Journald `systemd-journal-upload` supports the ability to send log events it gathers to a remote log host.

    Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'rationale', "
    Journald `systemd-journal-upload` supports the ability to send log events it gathers to a remote log host.

    Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'check', "
    Run the following command to verify `systemd-journal-upload` authentication is configured:

    ```
    # grep -P \"^ *URL=|^ *ServerKeyFile=|^ *ServerCertificateFile=|^ *TrustedCertificateFile=\" /etc/systemd/journal-upload.conf
    ```

    Verify the output matches per your environments certificate locations and the URL of the log server:

    _Example:_
    ```
    [Upload]
    URL=192.168.50.42
    ServerKeyFile=/etc/ssl/private/journal-upload.pem
    ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
    TrustedCertificateFile=/etc/ssl/ca/trusted.pem
    ```
  "
  desc  'fix', "
    Edit the `/etc/systemd/journal-upload.conf` file or a file in `/etc/systemd/journal-upload.conf.d` ending in `.conf` and ensure the following lines are set in the `[Upload]` section per your environment:

    ```
    [Upload]
    URL=192.168.50.42
    ServerKeyFile=/etc/ssl/private/journal-upload.pem
    ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
    TrustedCertificateFile=/etc/ssl/ca/trusted.pem
    ```

    Restart the service:

    ```
    # systemctl restart systemd-journal-upload
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.2.1.2'
  tag cis_number:            '6.2.2.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0602020102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  impact 0.5
  describe 'systemd-journal-upload authentication (6.2.2.1.2)' do
    skip 'operational: only applicable when forwarding to a remote journald collector; cert/auth config is site-specific.'
  end
end