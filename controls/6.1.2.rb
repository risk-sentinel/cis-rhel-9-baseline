# encoding: UTF-8

control 'C-6.1.2' do
  title 'Ensure filesystem integrity is regularly checked'
  desc  "
    Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.

    Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion.
  "
  desc  'rationale', "
    Periodic checking of the filesystem integrity is needed to detect changes to the filesystem.

    Periodic file checking allows the system administrator to determine on a regular basis if critical files have been changed in an unauthorized fashion.
  "
  desc  'check', "
    Run the following commands to verify a cron job scheduled to run the aide check.
    ```
    # grep -Ers '^([^#]+\\s+)?(\\/usr\\/s?bin\\/|^\\s*)aide(\\.wrapper)?\\s(--?\\S+\\s)*(--(check|update)|\\$AIDEARGS)\\b' /etc/cron.* /etc/crontab /var/spool/cron/
    ```
    Ensure a cron job in compliance with site policy is returned.

    - OR - 

    Run the following commands to verify that `aidecheck.service` and `aidecheck.timer` are enabled and `aidcheck.timer` is running
    ```
    # systemctl is-enabled aidecheck.service

    # systemctl is-enabled aidecheck.timer
    # systemctl status aidecheck.timer
    ```
  "
  desc  'fix', "
    - IF - `cron` will be used to schedule and run aide check

    Run the following command:
    ```
    # crontab -u root -e
    ```

    Add the following line to the crontab:
    ```
    0 5 * * * /usr/sbin/aide --check
    ```

    - OR - 

    - IF -  `aidecheck.service` and `aidecheck.timer` will be used to schedule and run aide check:

    Create or edit the file `/etc/systemd/system/aidecheck.service` and add the following lines:
    ```
    [Unit]
    Description=Aide Check

    [Service]
    Type=simple
    ExecStart=/usr/sbin/aide --check

    [Install]
    WantedBy=multi-user.target
    ```

    Create or edit the file `/etc/systemd/system/aidecheck.timer` and add the following lines:
    ```
    [Unit]
    Description=Aide check every day at 5AM

    [Timer]
    OnCalendar=*-*-* 05:00:00
    Unit=aidecheck.service

    [Install]
    WantedBy=multi-user.target
    ```

    Run the following commands:
    ```
    # chown root:root /etc/systemd/system/aidecheck.*
    # chmod 0644 /etc/systemd/system/aidecheck.*

    # systemctl daemon-reload

    # systemctl enable aidecheck.service
    # systemctl --now enable aidecheck.timer
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-2 a', 'SC-12 (3)']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AU-2 a', 'SC-12 (3)']
  tag cci:                   ['CCI-000123', 'CCI-002447']
  tag cis_rid:               '6.1.2'
  tag cis_number:            '6.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-060102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: a scheduled runtime integrity scan is N/A on an
  # ephemeral/immutable instance — integrity is established at image build and asserted
  # via AMI provenance (6.1.1). persistent keeps the scheduled-check assertion unchanged.
  if resolve_host_lifecycle(input('host_lifecycle')) == 'ephemeral'
    impact 0.0
    describe 'Scheduled AIDE integrity check N/A (host_lifecycle=ephemeral; integrity established at image build — see 6.1.1 AMI provenance)' do
      subject { true }
      it { is_expected.to eq true }
    end
  else
    impact 0.5
    describe.one do
      describe service('dailyaidecheck.timer') do
        it { should be_enabled }
      end
      describe command(%q{grep -rh aide /etc/cron.d /etc/crontab /etc/cron.daily /var/spool/cron 2>/dev/null}) do
        its('stdout') { should match(/aide/) }
      end
    end
  end
end