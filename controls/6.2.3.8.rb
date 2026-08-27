# encoding: UTF-8

control 'C-6.2.3.8' do
  title 'Ensure rsyslog logrotate is configured'
  desc  "
    The system includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageably large. The file `/etc/logrotate.d/rsyslog` is the configuration file used to rotate log files created by `rsyslog`.

    By keeping the log files smaller and more manageable, a system administrator can easily archive these files to another system and spend less time looking through inordinately large log files.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'rationale', "
    The system includes the capability of rotating log files regularly to avoid filling up the system with logs or making the logs unmanageably large. The file `/etc/logrotate.d/rsyslog` is the configuration file used to rotate log files created by `rsyslog`.

    By keeping the log files smaller and more manageable, a system administrator can easily archive these files to another system and spend less time looking through inordinately large log files.

    Note: This recommendation only applies if `rsyslog` is the chosen method for client side logging. Do not apply this recommendation if `systemd-journald` is used.
  "
  desc  'check', "
    Review `/etc/logrotate.conf` and `/etc/logrotate.d/*` and verify logs are rotated according to site policy.
    ```
    #!/usr/bin/env bash

    {   
        l_output=\"\" l_rotate_conf=\"\" #check for logrotate.conf file
        if [ -f /etc/logrotate.conf ]; then
            l_rotate_conf=\"/etc/logrotate.conf\"
        elif compgen -G \"/etc/logrotate.d/*.conf\" 2>/dev/null; then
            for file in /etc/logrotate.d/*.conf; do
                l_rotate_conf=\"$file\" 
            done
        elif systemctl is-active --quiet systemd-journal-upload.service; then
            echo -e \"- journald is in use on system\\n - recommendation is NA\"
        else  
            echo -e \"- logrotate is not configured\"
            l_output=\"$l_output\\n- rsyslog is in use and logrotate is not configured\"
        fi
        if [ -z \"$l_output\" ]; then # Provide output from checks
          echo -e \"\\n- Audit Result:\\n   REVIEW \\n - $l_rotate_conf and verify logs are rotated according to site policy.\"
       else
          echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output\"
       fi
    }
    ```
  "
  desc  'fix', "
    Edit `/etc/logrotate.conf` and `/etc/logrotate.d/*` to ensure logs are rotated according to site policy.

    _Example logrotate configuration that specifies log files be rotated weekly, keep 4 backlogs, compress old log files, ignores missing and empty log files, postrotate to reload rsyslog service after logs are rotated_
    ```
    /var/log/rsyslog/*.log {
        weekly
        rotate 4
        compress
        missingok
        notifempty
        postrotate
                /usr/bin/systemctl reload rsyslog.service >/dev/null || true
        endscript	
    }
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 (2)', 'AU-4']
  tag cci:                   ['CCI-001682', 'CCI-001848']
  tag cis_rid:               '6.2.3.8'
  tag cis_number:            '6.2.3.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020308r1_rule'
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
