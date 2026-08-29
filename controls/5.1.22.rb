# encoding: UTF-8

control 'C-5.1.22' do
  title 'Ensure sshd UsePAM is enabled'
  desc  "
    The `UsePAM` directive enables the Pluggable Authentication Module (PAM) interface. If set to `yes` this will enable PAM authentication using `ChallengeResponseAuthentication` and `PasswordAuthentication` directives in addition to PAM account and session module processing for all authentication types.

    When `usePAM` is set to `yes`, PAM runs through account and session types properly. This is important if you want to restrict access to services based off of IP, time or other factors of the account. Additionally, you can make sure users inherit certain environment variables on login or disallow access to the server
  "
  desc  'rationale', "
    The `UsePAM` directive enables the Pluggable Authentication Module (PAM) interface. If set to `yes` this will enable PAM authentication using `ChallengeResponseAuthentication` and `PasswordAuthentication` directives in addition to PAM account and session module processing for all authentication types.

    When `usePAM` is set to `yes`, PAM runs through account and session types properly. This is important if you want to restrict access to services based off of IP, time or other factors of the account. Additionally, you can make sure users inherit certain environment variables on login or disallow access to the server
  "
  desc  'check', "
    Run the following command to verify `UsePAM` is set to `yes`:

    ```
    # sshd -T | grep -i usepam

    usepam yes
    ```
  "
  desc  'fix', "
    Edit the `/etc/ssh/sshd_config` file to set the `UsePAM` parameter to `yes` above any `Include` entries as follows:

    ```
    UsePAM yes
    ```

    Note: First occurrence of an option takes precedence. If Include locations are enabled, used, and order of precedence is understood in your environment, the entry may be created in a file in Include location.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-7 a', 'IA-5 (1) (e)']
  tag ksi:                   ['KSI-CNA-ULN', 'KSI-IAM-APM', 'KSI-SVC-EIS']
  tag nist_r4:               ['IA-5 (1) (e)', 'SC-7 a']
  tag cci:                   ['CCI-001097', 'CCI-000200']
  tag cis_rid:               '5.1.22'
  tag cis_number:            '5.1.22'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050122r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe sshd_config do
    its('UsePAM') { should cmp 'yes' }
  end
end