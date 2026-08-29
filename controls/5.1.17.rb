# encoding: UTF-8

control 'C-5.1.17' do
  title 'Ensure sshd MaxStartups is configured'
  desc  "
    The `MaxStartups` parameter specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.

    To protect a system from denial of service due to a large number of pending authentication connection attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  desc  'rationale', "
    The `MaxStartups` parameter specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.

    To protect a system from denial of service due to a large number of pending authentication connection attempts, use the rate limiting function of MaxStartups to protect availability of sshd logins and prevent overwhelming the daemon.
  "
  desc  'check', "
    Run the following command to verify `MaxStartups` is `10:30:60` or more restrictive:

    ```
    # sshd -T | awk '$1 ~ /^\\s*maxstartups/{split($2, a, \":\");{if(a[1] > 10 || a[2] > 30 || a[3] > 60) print $0}}'

    ```

    Nothing should be returned
  "
  desc  'fix', "
    Edit the `/etc/ssh/sshd_config` file to set the `MaxStartups` parameter to `10:30:60` or more restrictive above any `Include` entries as follows:

    ```
    MaxStartups 10:30:60
    ```

    Note: First occurrence of a option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag ksi:                   ['KSI-CMT-LMC', 'KSI-CMT-RMV', 'KSI-MLA-EVC', 'KSI-SVC-ACM']
  tag nist_r4:               ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.1.17'
  tag cis_number:            '5.1.17'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050117r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe sshd_config do
    its('MaxStartups') { should cmp '10:30:60' }
  end
end