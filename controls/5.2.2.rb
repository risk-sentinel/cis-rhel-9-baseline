# encoding: UTF-8

control 'C-5.2.2' do
  title 'Ensure sudo commands use pty'
  desc  "
    `sudo` can be configured to run only from a pseudo terminal (`pseudo-pty`).

    Attackers can run a malicious program using `sudo` which would fork a background process that remains even when the main program has finished executing.
  "
  desc  'rationale', "
    `sudo` can be configured to run only from a pseudo terminal (`pseudo-pty`).

    Attackers can run a malicious program using `sudo` which would fork a background process that remains even when the main program has finished executing.
  "
  desc  'check', "
    Verify that `sudo` can only run other commands from a pseudo terminal.

    Run the following command to verify `Defaults use_pty` is set:

    ```
    # grep -rPi -- '^\\h*Defaults\\h+([^#\\n\\r]+,\\h*)?use_pty\\b' /etc/sudoers*
    ```

    Verify the output matches:

    ```
    /etc/sudoers:Defaults use_pty
    ```

    Run the follow command to to verify `Defaults !use_pty` is not set:

    ```
    # grep -rPi -- '^\\h*Defaults\\h+([^#\\n\\r]+,\\h*)?!use_pty\\b' /etc/sudoers*
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Edit the file `/etc/sudoers` with `visudo` or a file in `/etc/sudoers.d/` with `visudo -f ` and add the following line:

    ```
    Defaults use_pty
    ```

    Edit the file `/etc/sudoers` with `visudo` and any files in `/etc/sudoers.d/` with `visudo -f ` and remove any occurrence of `!use_pty`

    Note: 
    - sudo will read each file in `/etc/sudoers.d`, skipping file names that end in `~` or contain a `.` character to avoid causing problems with package manager or editor temporary/backup files. 
    - Files are parsed in sorted lexical order. That is, `/etc/sudoers.d/01_first` will be parsed before `/etc/sudoers.d/10_second`. 
    - Be aware that because the sorting is lexical, not numeric, `/etc/sudoers.d/1_whoops` would be loaded after `/etc/sudoers.d/10_second`. 
    - Using a consistent number of leading zeroes in the file names can be used to avoid such problems.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 a', 'AC-2 c']
  tag cci:                   ['CCI-002110', 'CCI-002113']
  tag cis_rid:               '5.2.2'
  tag cis_number:            '5.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure sudo commands use pty' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-050202r1_rule.'
  end
end
