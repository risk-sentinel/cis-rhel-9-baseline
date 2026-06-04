# encoding: UTF-8

control 'C-5.4.2.7' do
  title 'Ensure system accounts do not have a valid login shell'
  desc  "
    There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell. Furthermore, a user may add special accounts that are not intended to provide an interactive shell.

    It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the `nologin` shell. This prevents the account from potentially being used to run any commands.
  "
  desc  'rationale', "
    There are a number of accounts provided with most distributions that are used to manage applications and are not intended to provide an interactive shell. Furthermore, a user may add special accounts that are not intended to provide an interactive shell.

    It is important to make sure that accounts that are not being used by regular users are prevented from being used to provide an interactive shell. By default, most distributions set the password field for these accounts to an invalid string, but it is also recommended that the shell field in the password file be set to the `nologin` shell. This prevents the account from potentially being used to run any commands.
  "
  desc  'check', "
    Run the following command to verify system accounts, except for `root`, `halt`, `sync`, `shutdown` or `nfsnobody`, do not have a valid login shell:

    ```
    #!/usr/bin/env bash

    {
       l_valid_shells=\"^($(awk -F\\/ '$NF != \"nologin\" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' | paste -s -d '|' - ))$\"
       awk -v pat=\"$l_valid_shells\" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'\"$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)\"' || $3 == 65534) && $(NF) ~ pat) {print \"Service account: \\\"\" $1 \"\\\" has a valid shell: \" $7}' /etc/passwd
    }
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Run the following command to set the shell for any service accounts returned by the audit to `nologin`:

    ```
    # usermod -s $(command -v nologin) ```

    _Example script:_

    ```
    #!/usr/bin/env bash

    {
       l_valid_shells=\"^($( awk -F\\/ '$NF != \"nologin\" {print}' /etc/shells | sed -rn '/^\\//{s,/,\\\\\\\\/,g;p}' | paste -s -d '|' - ))$\"
       awk -v pat=\"$l_valid_shells\" -F: '($1!~/^(root|halt|sync|shutdown|nfsnobody)$/ && ($3<'\"$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)\"' || $3 == 65534) && $(NF) ~ pat) {system (\"usermod -s '\"$(command -v nologin)\"' \" $1)}' /etc/passwd
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.4.2.7'
  tag cis_number:            '5.4.2.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040207r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{awk -F: '($3<1000 && $1!="root" && $7!~/(nologin|false)$/ && $1!~/^(sync|shutdown|halt)$/){print $1}' /etc/passwd}) do
    its('stdout.strip') { should be_empty }
  end
end