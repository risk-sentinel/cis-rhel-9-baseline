# encoding: UTF-8

control 'C-6.2.3.6' do
  title 'Ensure rsyslog is configured to send logs to a remote log host'
  desc  "
    `rsyslog` supports the ability to send log events it gathers to a remote log host or to receive messages from remote hosts, thus enabling centralized log management.

    Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'rationale', "
    `rsyslog` supports the ability to send log events it gathers to a remote log host or to receive messages from remote hosts, thus enabling centralized log management.

    Storing log data on a remote host protects log integrity from local attacks. If an attacker gains root access on the local system, they could tamper with or remove log data that is stored on the local system.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'check', "
    Review the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files and verify that logs are sent to a central host:

    Note: The basic format is intended for users that configured their file use `@loghost.example.com` The advanced format is a more modern format that will audit formatting similar to that found in the remediation.

    basic format

    ```
    # grep \"^*.*[^I][^I]*@\" /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    ```

    Output should include `@@ `:

    _Example:_
    ```
    *.* @@loghost.example.com
    ```

    advanced format

    ```
    # grep -Psi -- '^\\s*([^#]+\\s+)?action\\(([^#]+\\s+)?\\btarget=\\\"?[^#\"]+\\\"?\\b' /etc/rsyslog.conf /etc/rsyslog.d/*.conf
    ```

    Output should include `target= `:

    _Example:_
    ```
    *.* action(type=\"omfwd\" target=\"loghost.example.com\" port=\"514\" protocol=\"tcp\"
    ```
  "
  desc  'fix', "
    Edit the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files and add the following line (where `loghost.example.com` is the name of your central log host). The `target` directive may either be a fully qualified domain name or an IP address.

    _Example:_
    ```
    *.* action(type=\"omfwd\" target=\"loghost.example.com\" port=\"514\" protocol=\"tcp\"
               action.resumeRetryCount=\"100\"
               queue.type=\"LinkedList\" queue.size=\"1000\")
    ```

    Run the following command to reload `rsyslog.service`:

    ```
    # systemctl reload-or-restart rsyslog.service
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.3.6'
  tag cis_number:            '6.2.3.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020306r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure rsyslog is configured to send logs to a remote log host' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-06020306r1_rule.'
  end
end
