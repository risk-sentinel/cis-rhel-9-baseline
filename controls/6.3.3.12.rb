# encoding: UTF-8

control 'C-6.3.3.12' do
  title 'Ensure login and logout events are collected'
  desc  "
    Monitor login and logout events. The parameters below track changes to files associated with login/logout events.
    - `/var/log/lastlog` - maintain records of the last time a user successfully logged in. 
    - `/var/run/faillock` - directory maintains records of login failures via the `pam_faillock` module.

    Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins.
  "
  desc  'rationale', "
    Monitor login and logout events. The parameters below track changes to files associated with login/logout events.
    - `/var/log/lastlog` - maintain records of the last time a user successfully logged in. 
    - `/var/run/faillock` - directory maintains records of login failures via the `pam_faillock` module.

    Monitoring login/logout events could provide a system administrator with information associated with brute force attacks against user logins.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # awk '/^ *-w/ \\
    &&(/\\/var\\/log\\/lastlog/ \\
      ||/\\/var\\/run\\/faillock/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -w /var/log/lastlog -p wa -k logins
    -w /var/run/faillock -p wa -k logins
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # auditctl -l | awk '/^ *-w/ \\
    &&(/\\/var\\/log\\/lastlog/ \\
      ||/\\/var\\/run\\/faillock/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    ```

    Verify the output matches:

    ```
    -w /var/log/lastlog -p wa -k logins
    -w /var/run/faillock -p wa -k logins
    ```
  "
  desc  'fix', "
    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor login and logout events.

    _Example:_

    ```
    # printf \"
    -w /var/log/lastlog -p wa -k logins
    -w /var/run/faillock -p wa -k logins
    \" >> /etc/audit/rules.d/50-login.rules
    ```

    Merge and load the rules into active configuration:

    ```
    # augenrules --load
    ```

    Check if reboot is required.

    ```
    # if [[ $(auditctl -s | grep \"enabled\") =~ \"2\" ]]; then printf \"Reboot required to load rules\\n\"; fi
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b', 'AU-3 a', 'SA-11 e']
  tag cci:                   ['CCI-000366', 'CCI-000130', 'CCI-003178']
  tag cis_rid:               '6.3.3.12'
  tag cis_number:            '6.3.3.12'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030312r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +logins|key=logins)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end