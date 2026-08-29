# encoding: UTF-8

control 'C-6.3.3.4' do
  title 'Ensure events that modify date and time information are collected'
  desc  "
    Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the;
    - `adjtimex` - tune kernel clock
    - `settimeofday` - set time using `timeval` and `timezone` structures
    - `stime` - using seconds since 1/1/1970
    - `clock_settime` - allows for the setting of several internal clocks and timers

    system calls have been executed. Further, ensure to write an audit record to the configured audit log file upon exit, tagging the records with a unique identifier such as \"time-change\".

    Unexpected changes in system date and/or time could be a sign of malicious activity on the system.
  "
  desc  'rationale', "
    Capture events where the system date and/or time has been modified. The parameters in this section are set to determine if the;
    - `adjtimex` - tune kernel clock
    - `settimeofday` - set time using `timeval` and `timezone` structures
    - `stime` - using seconds since 1/1/1970
    - `clock_settime` - allows for the setting of several internal clocks and timers

    system calls have been executed. Further, ensure to write an audit record to the configured audit log file upon exit, tagging the records with a unique identifier such as \"time-change\".

    Unexpected changes in system date and/or time could be a sign of malicious activity on the system.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # {
     awk '/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&/ -S/ \\
     &&(/adjtimex/ \\
       ||/settimeofday/ \\
       ||/clock_settime/ ) \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules

     awk '/^ *-w/ \\
     &&/\\/etc\\/localtime/ \\
     &&/ +-p *wa/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    }
    ```

    Verify output of matches:

    ```
    -a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
    -a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
    -a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
    -a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
    -w /etc/localtime -p wa -k time-change
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # {
     auditctl -l | awk '/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&/ -S/ \\
     &&(/adjtimex/ \\
       ||/settimeofday/ \\
       ||/clock_settime/ ) \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

     auditctl -l | awk '/^ *-w/ \\
     &&/\\/etc\\/localtime/ \\
     &&/ +-p *wa/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    }
    ```

    Verify the output includes:

    ```
    -a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change
    -a always,exit -F arch=b32 -S settimeofday,adjtimex -F key=time-change
    -a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -F key=time-change
    -a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -F key=time-change
    -w /etc/localtime -p wa -k time-change
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor events that modify date and time information.

    Example:

    ```
    # printf \"
    -a always,exit -F arch=b64 -S adjtimex,settimeofday -k time-change
    -a always,exit -F arch=b32 -S adjtimex,settimeofday -k time-change
    -a always,exit -F arch=b64 -S clock_settime -F a0=0x0 -k time-change
    -a always,exit -F arch=b32 -S clock_settime -F a0=0x0 -k time-change
    -w /etc/localtime -p wa -k time-change
    \" >> /etc/audit/rules.d/50-time-change.rules
    ```

    Load audit rules

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
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-2 a', 'AU-3 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-JIT', 'KSI-IAM-SNU', 'KSI-IAM-SUS', 'KSI-MLA-OSM']
  tag nist_r4:               ['AC-2 a', 'AU-3']
  tag cci:                   ['CCI-002110', 'CCI-000130']
  tag cis_rid:               '6.3.3.4'
  tag cis_number:            '6.3.3.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030304r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +time-change|key=time-change)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end