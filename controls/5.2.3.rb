# encoding: UTF-8

control 'C-5.2.3' do
  title 'Ensure sudo log file exists'
  desc  "
    The `Defaults logfile` entry sets the path to the sudo log file. Setting a path turns on logging to a file; negating this option turns it off. By default, sudo logs via syslog.

    Defining a dedicated log file for sudo simplifies auditing of sudo commands and creation of auditd rules for sudo.
  "
  desc  'rationale', "
    The `Defaults logfile` entry sets the path to the sudo log file. Setting a path turns on logging to a file; negating this option turns it off. By default, sudo logs via syslog.

    Defining a dedicated log file for sudo simplifies auditing of sudo commands and creation of auditd rules for sudo.
  "
  desc  'check', "
    Run the following command to verify that sudo has a custom log file configured

    ```
    # grep -rPsi \"^\\h*Defaults\\h+([^#]+,\\h*)?logfile\\h*=\\h*(\\\"|\\')?\\H+(\\\"|\\')?(,\\h*\\H+\\h*)*\\h*(#.*)?$\" /etc/sudoers*
    ```

    _Example output:_

    ```
    Defaults logfile=\"/var/log/sudo.log\"
    ```
  "
  desc  'fix', "
    Edit the file `/etc/sudoers` or a file in `/etc/sudoers.d/` with `visudo -f ` and add the following line:

    ```
    Defaults  logfile=\" \"
    ```

    _Example_
    ```
    Defaults logfile=\"/var/log/sudo.log\"
    ```

    Notes: 
    - sudo will read each file in `/etc/sudoers.d`, skipping file names that end in `~` or contain a `.` character to avoid causing problems with package manager or editor temporary/backup files. 
    - Files are parsed in sorted lexical order. That is, `/etc/sudoers.d/01_first` will be parsed before `/etc/sudoers.d/10_second`. 
    - Be aware that because the sorting is lexical, not numeric, `/etc/sudoers.d/1_whoops` would be loaded after `/etc/sudoers.d/10_second`. 
    - Using a consistent number of leading zeroes in the file names can be used to avoid such problems.
  "
  tag severity:              'medium'
  tag nist:                  ['IA-2 (2)', 'AU-3 a']
  tag cci:                   ['CCI-000766', 'CCI-000130']
  tag cis_rid:               '5.2.3'
  tag cis_number:            '5.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,)?\h*logfile\h*=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end