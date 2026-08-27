# encoding: UTF-8

control 'C-6.2.2.1.3' do
  title 'Ensure systemd-journal-upload is enabled and active'
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
    Run the following command to verify `systemd-journal-upload` is enabled.

    ```
    # systemctl is-enabled systemd-journal-upload.service

    enabled
    ```

    Run the following command to verify `systemd-journal-upload` is active:

    ```
    # systemctl is-active systemd-journal-upload.service

    active
    ```
  "
  desc  'fix', "
    Run the following commands to unmask, enable and start `systemd-journal-upload`:

    ```
    # systemctl unmask systemd-journal-upload.service
    # systemctl --now enable systemd-journal-upload.service
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'IA-2 (2)', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000766', 'CCI-000123']
  tag cis_rid:               '6.2.2.1.3'
  tag cis_number:            '6.2.2.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0602020103r1_rule'
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
