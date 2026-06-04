# encoding: UTF-8

control 'C-6.3.3.11' do
  title 'Ensure session initiation information is collected'
  desc  "
    Monitor session initiation events. The parameters in this section track changes to the files associated with session events.
    - `/var/run/utmp` - tracks all currently logged in users.
    - `/var/log/wtmp` - file tracks logins, logouts, shutdown, and reboot events.
    - `/var/log/btmp` - keeps track of failed login attempts and can be read by entering the command `/usr/bin/last -f /var/log/btmp`.

    All audit records will be tagged with the identifier \"session.\"

    Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally log in).
  "
  desc  'rationale', "
    Monitor session initiation events. The parameters in this section track changes to the files associated with session events.
    - `/var/run/utmp` - tracks all currently logged in users.
    - `/var/log/wtmp` - file tracks logins, logouts, shutdown, and reboot events.
    - `/var/log/btmp` - keeps track of failed login attempts and can be read by entering the command `/usr/bin/last -f /var/log/btmp`.

    All audit records will be tagged with the identifier \"session.\"

    Monitoring these files for changes could alert a system administrator to logins occurring at unusual hours, which could indicate intruder activity (i.e. a user logging in at a time when they do not normally log in).
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # awk '/^ *-w/ \\
    &&(/\\/var\\/run\\/utmp/ \\
      ||/\\/var\\/log\\/wtmp/ \\
      ||/\\/var\\/log\\/btmp/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -w /var/run/utmp -p wa -k session
    -w /var/log/wtmp -p wa -k session
    -w /var/log/btmp -p wa -k session
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # auditctl -l | awk '/^ *-w/ \\
    &&(/\\/var\\/run\\/utmp/ \\
      ||/\\/var\\/log\\/wtmp/ \\
      ||/\\/var\\/log\\/btmp/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    ```

    Verify the output matches:

    ```
    -w /var/run/utmp -p wa -k session
    -w /var/log/wtmp -p wa -k session
    -w /var/log/btmp -p wa -k session
    ```
  "
  desc  'fix', "
    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor session initiation information.

    _Example:_

    ```
    # printf \"
    -w /var/run/utmp -p wa -k session
    -w /var/log/wtmp -p wa -k session
    -w /var/log/btmp -p wa -k session
    \" >> /etc/audit/rules.d/50-session.rules
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
  tag nist:                  ['CM-6 b', 'AU-3 a']
  tag cci:                   ['CCI-000366', 'CCI-000130']
  tag cis_rid:               '6.3.3.11'
  tag cis_number:            '6.3.3.11'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030311r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +session|key=session)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end