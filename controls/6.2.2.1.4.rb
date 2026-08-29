# encoding: UTF-8

control 'C-6.2.2.1.4' do
  title 'Ensure systemd-journal-remote service is not in use'
  desc  "
    Journald `systemd-journal-remote` supports the ability to receive messages from remote hosts, thus acting as a log server. Clients should not receive data from other hosts.

    Note: 
    - The same package, `systemd-journal-remote`, is used for both sending logs to remote hosts and receiving incoming logs.
    - With regards to receiving logs, there are two services; `systemd-journal-remote.socket` and `systemd-journal-remote.service`.

    If a client is configured to also receive data, thus turning it into a server, the client system is acting outside it's operational boundary.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'rationale', "
    Journald `systemd-journal-remote` supports the ability to receive messages from remote hosts, thus acting as a log server. Clients should not receive data from other hosts.

    Note: 
    - The same package, `systemd-journal-remote`, is used for both sending logs to remote hosts and receiving incoming logs.
    - With regards to receiving logs, there are two services; `systemd-journal-remote.socket` and `systemd-journal-remote.service`.

    If a client is configured to also receive data, thus turning it into a server, the client system is acting outside it's operational boundary.

    Note: This recommendation only applies if `journald` is the chosen method for client side logging. Do not apply this recommendation if `rsyslog` is used.
  "
  desc  'check', "
    Run the following command to verify `systemd-journal-remote.socket` and `systemd-journal-remote.service` are not enabled:

    ```
    # systemctl is-enabled systemd-journal-remote.socket systemd-journal-remote.service | grep -P -- '^enabled'
    ```
    Nothing should be returned


    Run the following command to verify `systemd-journal-remote.socket` and `systemd-journal-remote.service` are not active:

    ```
    # systemctl is-active systemd-journal-remote.socket systemd-journal-remote.service | grep -P -- '^active'
    ```
    Nothing should be returned
  "
  desc  'fix', "
    Run the following commands to stop and mask `systemd-journal-remote.socket` and systemd-journal-remote.service:

    ```
    # systemctl stop systemd-journal-remote.socket systemd-journal-remote.service
    # systemctl mask systemd-journal-remote.socket systemd-journal-remote.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '6.2.2.1.4'
  tag cis_number:            '6.2.2.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0602020104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('systemd-journal-remote.socket') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end