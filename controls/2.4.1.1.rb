# encoding: UTF-8

control 'C-2.4.1.1' do
  title 'Ensure cron daemon is enabled and active'
  desc  "
    The `cron` daemon is used to execute batch jobs on the system.

    While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and `cron` is used to execute them.
  "
  desc  'rationale', "
    The `cron` daemon is used to execute batch jobs on the system.

    While there may not be user jobs that need to be run on the system, the system does have maintenance jobs that may include security monitoring that have to run, and `cron` is used to execute them.
  "
  desc  'check', "
    - IF - cron is installed on the system:

    Run the following command to verify `cron` is enabled:

    ```
    # systemctl list-unit-files | awk '$1~/^crond?\\.service/{print $2}'

    enabled
    ```

    Run the following command to verify that `cron` is active:

    ```
    # systemctl list-units | awk '$1~/^crond?\\.service/{print $3}'

    active
    ```
  "
  desc  'fix', "
    - IF - cron is installed on the system:

    Run the following commands to unmask, enable, and start `cron`:

    ```
    # systemctl unmask \"$(systemctl list-unit-files | awk '$1~/^crond?\\.service/{print $1}')\"
    # systemctl --now enable \"$(systemctl list-unit-files | awk '$1~/^crond?\\.service/{print $1}')\"
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '2.4.1.1'
  tag cis_number:            '2.4.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-02040101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('crond') do
    it { should be_enabled }
    it { should be_running }
  end
end