# encoding: UTF-8

control 'C-6.3.2.3' do
  title 'Ensure system is disabled when audit logs are full'
  desc  "
    The `auditd` daemon can be configured to halt the system or put the system in single user mode, if no free space is available or an error is detected on the partition that holds the audit log files.

    The `disk_full_action` parameter tells the system what action to take when no free space is available on the partition that holds the audit log files. Valid values are `ignore`, `syslog`, `rotate`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon will issue a syslog message but no other action is taken
    - `syslog`, the audit daemon will issue a warning to syslog
    - `rotate`, the audit daemon will rotate logs, losing the oldest to free up space
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script. The script is also responsible for telling the auditd daemon to resume logging once its completed its action
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    The `disk_error_action` parameter tells the system what action to take when an error is detected on the partition that holds the audit log files. Valid values are `ignore`, `syslog`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon will not take any action
    - `syslog`, the audit daemon will issue no more than 5 consecutive warnings to syslog
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability.
  "
  desc  'rationale', "
    The `auditd` daemon can be configured to halt the system or put the system in single user mode, if no free space is available or an error is detected on the partition that holds the audit log files.

    The `disk_full_action` parameter tells the system what action to take when no free space is available on the partition that holds the audit log files. Valid values are `ignore`, `syslog`, `rotate`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon will issue a syslog message but no other action is taken
    - `syslog`, the audit daemon will issue a warning to syslog
    - `rotate`, the audit daemon will rotate logs, losing the oldest to free up space
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script. The script is also responsible for telling the auditd daemon to resume logging once its completed its action
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    The `disk_error_action` parameter tells the system what action to take when an error is detected on the partition that holds the audit log files. Valid values are `ignore`, `syslog`, `exec`, `suspend`, `single`, and `halt`.
    - `ignore`, the audit daemon will not take any action
    - `syslog`, the audit daemon will issue no more than 5 consecutive warnings to syslog
    - `exec`,   /path-to-script will execute the script. You cannot pass parameters to the script
    - `suspend`, the audit daemon will stop writing records to the disk
    - `single`, the audit daemon will put the computer system in single user mode
    - `halt`, the audit daemon will shut down the system

    In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds the benefit of the system's availability.
  "
  desc  'check', "
    Run the following command and verify the `disk_full_action` is set to either `halt` or `single`:

    ```
    # grep -P -- '^\\h*disk_full_action\\h*=\\h*(halt|single)\\b' /etc/audit/auditd.conf

    disk_full_action = ```

    Run the following command and verify the `disk_error_action` is set to `syslog`, `single`, or `halt`:

    ```
    # grep -P -- '^\\h*disk_error_action\\h*=\\h*(syslog|single|halt)\\b' /etc/audit/auditd.conf

    disk_error_action = ```
  "
  desc  'fix', "
    Set one of the following parameters in `/etc/audit/auditd.conf` depending on your local security policies. 

    ```
    disk_full_action = disk_error_action = ```

    _Example:_

    ```
    disk_full_action = halt
    disk_error_action = halt
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-2 a', 'AU-4']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-MLA-LET', 'KSI-MLA-OSM', 'KSI-MLA-RVL']
  tag nist_r4:               ['AU-2 a', 'AU-4']
  tag cci:                   ['CCI-000123', 'CCI-001848']
  tag cis_rid:               '6.3.2.3'
  tag cis_number:            '6.3.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -E '^\s*(admin_space_left_action|disk_full_action)\s*=\s*(halt|single)' /etc/audit/auditd.conf}) do
    its('stdout') { should match(/\S/) }
  end

  # log_pipeline axis: defense-in-depth — when logs ship off-box, also prove durable
  # CloudWatch ingestion (the on-box buffer above guards against ship failures).
  if log_offbox?
    cwl = cw_ingestion
    if cwl.available?
      describe cwl do
        it { should be_ingesting_within(input('cloudwatch_max_ingestion_lag')) }
      end
    else
      describe 'Off-box log durability (live CloudWatch read unavailable)' do
        skip "log_pipeline ships off-box but CloudWatch ingestion could not be read live (#{cwl.error}); evidence supplied by SAF attestation."
      end
    end
  end
end
