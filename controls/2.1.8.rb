# encoding: UTF-8

control 'C-2.1.8' do
  title 'Ensure message access server services are not in use'
  desc  "
    `dovecot` and `cyrus-imapd` are open source IMAP and POP3 server packages for Linux based systems.

    Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface.

    Note: Several IMAP/POP3 servers exist and can use other service names. These should also be audited and the packages removed if not required.
  "
  desc  'rationale', "
    `dovecot` and `cyrus-imapd` are open source IMAP and POP3 server packages for Linux based systems.

    Unless POP3 and/or IMAP servers are to be provided by this system, it is recommended that the package be removed to reduce the potential attack surface.

    Note: Several IMAP/POP3 servers exist and can use other service names. These should also be audited and the packages removed if not required.
  "
  desc  'check', "
    Run the following command to verify `dovecot` and `cyrus-imapd` are not installed:

    ```
    # rpm -q dovecot cyrus-imapd

    package dovecot is not installed
    package cyrus-imapd is not installed
    ```
    - OR -

    - IF - a package is installed and is required for dependencies:

    Run the following commands to verify `dovecot.socket`, `dovecot.service`, and `cyrus-imapd.service` are not enabled:

    ```
    # systemctl is-enabled dovecot.socket dovecot.service cyrus-imapd.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `dovecot.socket`, `dovecot.service`, and `cyrus-imapd.service` are not active:

    ```
    # systemctl is-active dovecot.socket dovecot.service cyrus-imapd.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `dovecot.socket`, `dovecot.service`, and `cyrus-imapd.service`, and remove `dovecot` and `cyrus-imapd` packages:

    ```
    # systemctl stop dovecot.socket dovecot.service cyrus-imapd.service
    # dnf remove dovecot cyrus-imapd
    ```

    - OR -

    - IF - a package is installed and is required for dependencies:

    Run the following commands to stop and mask `dovecot.socket`, `dovecot.service`, and `cyrus-imapd.service`:

    ```
    # systemctl stop dovecot.socket dovecot.service cyrus-imapd.service
    # systemctl mask dovecot.socket dovecot.service cyrus-imapd.service
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.8'
  tag cis_number:            '2.1.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020108r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('dovecot') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
  describe service('dovecot.socket') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end