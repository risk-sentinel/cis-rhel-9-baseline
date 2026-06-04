# encoding: UTF-8

control 'C-6.2.1.4' do
  title 'Ensure only one logging system is in use'
  desc  "
    Best practices recommend that a single centralized logging system be used for log management, choose a single service either `rsyslog` - OR - `journald` to be used as a single centralized logging system.

    Configuring only one logging service either `rsyslog` - OR - `journald` avoids redundancy, optimizes resources, simplifies configuration and management, and ensures consistency.
  "
  desc  'rationale', "
    Best practices recommend that a single centralized logging system be used for log management, choose a single service either `rsyslog` - OR - `journald` to be used as a single centralized logging system.

    Configuring only one logging service either `rsyslog` - OR - `journald` avoids redundancy, optimizes resources, simplifies configuration and management, and ensures consistency.
  "
  desc  'check', "
    Run the following script to ensure only one logging system is in use:

    ```
    #!/usr/bin/env bash

    {
        l_output=\"\" l_output2=\"\" # Check the status of rsyslog and journald
        if systemctl is-active --quiet rsyslog; then
            l_output=\"$l_output\\n - rsyslog is in use\\n- follow the recommendations in Configure rsyslog subsection only\"
        elif systemctl is-active --quiet systemd-journald; then
            l_output=\"$l_output\\n - journald is in use\\n- follow the recommendations in Configure journald subsection only\"
        else
            echo -e \"unable to determine system logging\"
            l_output2=\"$l_output2\\n - unable to determine system logging\\n- Configure only ONE system logging: rsyslog OR journald\"
        fi
        if [ -z \"$l_output2\" ]; then  # Provide audit results
            echo -e \"\\n- Audit Result:\\n   PASS \\n$l_output\\n\"
        else
            echo -e \"\\n- Audit Result:\\n   FAIL \\n - Reason(s) for audit failure:\\n$l_output2\"
        fi
    }
    ```
  "
  desc  'fix', "
    1. Determine whether to use `journald` - OR - `rsyslog` depending on site needs
    2. Configure `systemd-jounald.service` 
    3. Configure only ONE either `journald` - OR - `rsyslog` and complete the recommendations in that subsection
    4. Return to this recommendation to ensure only one logging system is in use
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '6.2.1.4'
  tag cis_number:            '6.2.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06020104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  impact 0.5
  describe 'only one logging system in use (6.2.1.4)' do
    skip 'operational: the choice of journald-only vs rsyslog-primary is a consumer logging-architecture decision; operator attests the single configured pipeline.'
  end
end