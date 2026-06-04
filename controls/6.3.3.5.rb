# encoding: UTF-8

control 'C-6.3.3.5' do
  title 'Ensure events that modify the system\'s network environment are collected'
  desc  "
    Record changes to network environment files or system calls. The below parameters monitors the following system calls, and write an audit event on system call exit:
    - `sethostname` - set the systems host name
    - `setdomainname` - set the systems domain name

    The files being monitored are:
    - `/etc/issue` and `/etc/issue.net` - messages displayed pre-login
    - `/etc/hosts` - file containing host names and associated IP addresses
    - `/etc/hostname` - file contains the system's host name
    - `/etc/sysconfig/network` - additional information that is valid to all network interfaces
    - `/etc/sysconfig/network-scripts/` - directory containing network interface scripts and configurations files
    - `/etc/NetworkManager/` - directory contains configuration files and settings used by the `NetworkManager`

    Monitoring `sethostname` and `setdomainname` will identify potential unauthorized changes to host and domain name of a system. The changing of these names could potentially break security parameters that are set based on those names. The `/etc/hosts` file is monitored for changes that can indicate an unauthorized intruder is trying to change machine associations with IP addresses and trick users and processes into connecting to unintended machines. Monitoring `/etc/issue` and `/etc/issue.net` is important, as intruders could put disinformation into those files and trick users into providing information to the intruder. Monitoring `/etc/sysconfig/network` is important as it can show if network interfaces or scripts are being modified in a way that can lead to the machine becoming unavailable or compromised. All audit records should have a relevant tag associated with them.
  "
  desc  'rationale', "
    Record changes to network environment files or system calls. The below parameters monitors the following system calls, and write an audit event on system call exit:
    - `sethostname` - set the systems host name
    - `setdomainname` - set the systems domain name

    The files being monitored are:
    - `/etc/issue` and `/etc/issue.net` - messages displayed pre-login
    - `/etc/hosts` - file containing host names and associated IP addresses
    - `/etc/hostname` - file contains the system's host name
    - `/etc/sysconfig/network` - additional information that is valid to all network interfaces
    - `/etc/sysconfig/network-scripts/` - directory containing network interface scripts and configurations files
    - `/etc/NetworkManager/` - directory contains configuration files and settings used by the `NetworkManager`

    Monitoring `sethostname` and `setdomainname` will identify potential unauthorized changes to host and domain name of a system. The changing of these names could potentially break security parameters that are set based on those names. The `/etc/hosts` file is monitored for changes that can indicate an unauthorized intruder is trying to change machine associations with IP addresses and trick users and processes into connecting to unintended machines. Monitoring `/etc/issue` and `/etc/issue.net` is important, as intruders could put disinformation into those files and trick users into providing information to the intruder. Monitoring `/etc/sysconfig/network` is important as it can show if network interfaces or scripts are being modified in a way that can lead to the machine becoming unavailable or compromised. All audit records should have a relevant tag associated with them.
  "
  desc  'check', "
    On disk configuration

    Run the following commands to check the on disk rules:

    ```
    # {
    # Check for syscalls related to hostname and domainname change
    awk '/^*-a *always, exit/ \\
    && /-F *arch=b(32|64)/ \\
    && /-S/ && (/sethostname/ \\
    || /setdomainname/) \\
    && (/skey= *[!-~]* *$/ || /-k *[!-~]* *$/)' /etc/audit/rules.d/*.rules

    # Check for file watches on network-related files
    awk '/^ *-w/ \\
    && (/etc\\/issue/ \\
    || /etc\\/issue.net/ \\
    || /etc\\/hosts/ \\
    || /etc\\/sysconfig\\/network/ \\
    || /etc\\/hostname/ \\
    || /etc\\/NetworkManager/) \\
    && / +-p *wa/ \\
    && (/ key= *[!-~]* *$/ || /-k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
    -a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/hostname -p wa -k system-locale
    -w /etc/sysconfig/network -p wa -k system-locale
    -w /etc/sysconfig/network-scripts/ -p wa -k system-locale
    -w /etc/NetworkManager -p wa -k system-locale
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # {
     auditctl -l | awk '/^ *-a *always,exit/ \\
     &&/ -F *arch=b(32|64)/ \\
     &&/ -S/ \\
     &&(/sethostname/ \\
       ||/setdomainname/) \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

     auditctl -l | awk '/^ *-w/ \\
     &&(/etc\\/issue/ \\
       || /etc\\/issue.net/ \\
       || /etc\\/hosts/ \\
       || /etc\\/sysconfig\\/network/ \\
       || /etc\\/hostname/ \\
       || /etc\\/NetworkManager/) \\
     &&/ +-p *wa/ \\
     &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    }
    ```

    Verify the output includes:

    ```
    -a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale
    -a always,exit -F arch=b32 -S sethostname,setdomainname -F key=system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/hostname -p wa -k system-locale
    -w /etc/sysconfig/network -p wa -k system-locale
    -w /etc/sysconfig/network-scripts -p wa -k system-locale
    -w /etc/NetworkManager -p wa -k system-locale
    ```
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor events that modify the system's network environment.

    Example:

    ```
    # printf \"
    -a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
    -a always,exit -F arch=b32 -S sethostname,setdomainname -k system-locale
    -w /etc/issue -p wa -k system-locale
    -w /etc/issue.net -p wa -k system-locale
    -w /etc/hosts -p wa -k system-locale
    -w /etc/hostname -p wa -k system-locale
    -w /etc/sysconfig/network -p wa -k system-locale
    -w /etc/sysconfig/network-scripts/ -p wa -k system-locale
    -w /etc/NetworkManager -p wa -k system-locale
    \" >> /etc/audit/rules.d/50-system_locale.rules
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
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 a', 'AU-3 a']
  tag cci:                   ['CCI-002110', 'CCI-000130']
  tag cis_rid:               '6.3.3.5'
  tag cis_number:            '6.3.3.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030305r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +system-locale|key=system-locale)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end