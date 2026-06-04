# encoding: UTF-8

control 'C-5.4.2.8' do
  title 'Ensure accounts without a valid login shell are locked'
  desc  "
    There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell. Furthermore, a user may add special accounts that are not intended to provide an interactive shell.

    It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the `nologin` shell. This prevents the account from potentially being used to run any commands.
  "
  desc  'rationale', "
    There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell. Furthermore, a user may add special accounts that are not intended to provide an interactive shell.

    It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the `nologin` shell. This prevents the account from potentially being used to run any commands.
  "
  desc  'check', "
    Run the following script to verify all non-root accounts without a valid login shell are locked.

    ```
    #!/usr/bin/env bash

    {
       l_valid_shells=\"^($(awk -F\\/ '$NF != \"nologin\" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' | paste -s -d '|' - ))$\"
       while IFS= read -r l_user; do
          passwd -S \"$l_user\" | awk '$2 !~ /^L/ {print \"Account: \\\"\" $1 \"\\\" does not have a valid login shell and is not locked\"}'
       done < <(awk -v pat=\"$l_valid_shells\" -F: '($1 != \"root\" && $(NF) !~ pat) {print $1}' /etc/passwd)
    }
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Run the following command to lock any non-root accounts without a valid login shell returned by the audit:

    ```
    # usermod -L ```

    _Example script:_:

    ```
    #!/usr/bin/env bash

    {
       l_valid_shells=\"^($(awk -F\\/ '$NF != \"nologin\" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' | paste -s -d '|' - ))$\"
       while IFS= read -r l_user; do
          passwd -S \"$l_user\" | awk '$2 !~ /^L/ {system (\"usermod -L \" $1)}'
       done < <(awk -v pat=\"$l_valid_shells\" -F: '($1 != \"root\" && $(NF) !~ pat) {print $1}' /etc/passwd)
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.4.2.8'
  tag cis_number:            '5.4.2.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040208r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{for u in $(awk -F: '($7~/(nologin|false)$/){print $1}' /etc/passwd); do s=$(awk -F: -v u="$u" '($1==u){print $2}' /etc/shadow); f=${s:0:1}; [ "$f" != "!" ] && [ "$f" != "*" ] && echo "$u"; done}) do
    its('stdout.strip') { should be_empty }
  end
end