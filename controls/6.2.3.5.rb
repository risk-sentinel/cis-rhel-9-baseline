# encoding: UTF-8

control 'C-6.2.3.5' do
  title 'Ensure rsyslog logging is configured'
  desc  "
    The `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files specifies rules for logging and which files are to be used to log certain classes of messages.

    A great deal of important security-related information is sent via `rsyslog` (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.).

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `journald` is used.
  "
  desc  'rationale', "
    The `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files specifies rules for logging and which files are to be used to log certain classes of messages.

    A great deal of important security-related information is sent via `rsyslog` (e.g., successful and failed su attempts, failed login attempts, root login attempts, etc.).

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `journald` is used.
  "
  desc  'check', "
    Review the contents of `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files to ensure appropriate logging is set. In addition, run the following command and verify that the log files are logging information as expected:

    ```
    # ls -l /var/log/maillog
    ```
  "
  desc  'fix', "
    Edit the following lines in the `/etc/rsyslog.conf` and `/etc/rsyslog.d/*.conf` files as appropriate for your environment.

    Note: The below configuration is shown for example purposes only. Due care should be given to how the organization wishes to store log data.

    ```
    *.emerg                                  :omusrmsg:*
    auth,authpriv.*                          /var/log/secure
    mail.*                                  -/var/log/mail
    mail.info                               -/var/log/mail.info
    mail.warning                            -/var/log/mail.warn
    mail.err                                 /var/log/mail.err
    cron.*                                   /var/log/cron
    *.=warning;*.=err                       -/var/log/warn
    *.crit                                   /var/log/warn
    *.*;mail.none;news.none                 -/var/log/messages
    local0,local1.*                         -/var/log/localmessages
    local2,local3.*                         -/var/log/localmessages
    local4,local5.*                         -/var/log/localmessages
    local6,local7.*                         -/var/log/localmessages
    ```

    Run the following command to reload the `rsyslogd` configuration:

    ```
    # systemctl restart rsyslog
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag nist_r4:               ['AC-2 f', 'AU-2 a', 'IA-2 (2)']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.3.5'
  tag cis_number:            '6.2.3.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020305r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # log_pipeline axis: off-box forwarding/retention is proven by durable CloudWatch
  # ingestion (e.g. via the CloudWatch agent); onbox => logs retained on-box (N/A).
  if log_offbox?
    impact 0.5
    cwl = cw_ingestion
    only_if("log_pipeline ships off-box but CloudWatch ingestion could not be read live (#{cwl.error}); evidence supplied by SAF attestation.") { cwl.available? }
    describe cwl do
      it { should be_ingesting_within(input('cloudwatch_max_ingestion_lag')) }
    end
  else
    impact 0.0
    describe 'Off-box log pipeline N/A (log_pipeline=onbox; logs retained on-box)' do
      subject { true }
      it { is_expected.to eq true }
    end
  end
end
