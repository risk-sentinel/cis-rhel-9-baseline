# encoding: UTF-8

control 'C-6.3.3.8' do
  title 'Ensure events that modify user/group information are collected'
  desc  "
    Record events affecting the modification of user or group information, including that of passwords and old passwords if in use.
    - `/etc/group` - system groups
    - `/etc/passwd` - system users
    - `/etc/gshadow` - encrypted password for each group
    - `/etc/shadow` - system user passwords
    - `/etc/security/opasswd` - storage of old passwords if the relevant PAM module is in use
    - `/etc/nsswitch.conf` - file configures how the system uses various databases and name resolution mechanisms
    - `/etc/pam.conf` - file determines the authentication services to be used, and the order in which the services are used.
    - `/etc/pam.d` - directory contains the PAM configuration files for each PAM-aware application.

    The parameters in this section will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) and tag them with the identifier \"identity\" in the audit log file.

    Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts.
  "
  desc  'rationale', "
    Record events affecting the modification of user or group information, including that of passwords and old passwords if in use.
    - `/etc/group` - system groups
    - `/etc/passwd` - system users
    - `/etc/gshadow` - encrypted password for each group
    - `/etc/shadow` - system user passwords
    - `/etc/security/opasswd` - storage of old passwords if the relevant PAM module is in use
    - `/etc/nsswitch.conf` - file configures how the system uses various databases and name resolution mechanisms
    - `/etc/pam.conf` - file determines the authentication services to be used, and the order in which the services are used.
    - `/etc/pam.d` - directory contains the PAM configuration files for each PAM-aware application.

    The parameters in this section will watch the files to see if they have been opened for write or have had attribute changes (e.g. permissions) and tag them with the identifier \"identity\" in the audit log file.

    Unexpected changes to these files could be an indication that the system has been compromised and that an unauthorized user is attempting to hide their activities or compromise additional accounts.
  "
  desc  'check', "
    On disk configuration

    Run the following command to check the on disk rules:

    ```
    # awk '/^ *-w/ \\
    &&(/\\/etc\\/group/ \\
      ||/\\/etc\\/passwd/ \\
      ||/\\/etc\\/gshadow/ \\
      ||/\\/etc\\/shadow/ \\
      ||/\\/etc\\/security\\/opasswd/ \\
      ||/\\/etc\\/nsswitch.conf/ \\
      ||/\\/etc\\/pam.conf/ \\
      ||/\\/etc\\/pam.d/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules
    ```

    Verify the output matches:

    ```
    -w /etc/group -p wa -k identity
    -w /etc/passwd -p wa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/security/opasswd -p wa -k identity
    -w /etc/nsswitch.conf -p wa -k identity
    -w /etc/pam.conf -p wa -k identity
    -w /etc/pam.d -p wa -k identity
    ```

    Running configuration

    Run the following command to check loaded rules:

    ```
    # auditctl -l | awk '/^ *-w/ \\
    &&(/\\/etc\\/group/ \\
      ||/\\/etc\\/passwd/ \\
      ||/\\/etc\\/gshadow/ \\
      ||/\\/etc\\/shadow/ \\
      ||/\\/etc\\/security\\/opasswd/ \\
      ||/\\/etc\\/nsswitch.conf/ \\
      ||/\\/etc\\/pam.conf/ \\
      ||/\\/etc\\/pam.d/) \\
    &&/ +-p *wa/ \\
    &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'
    ```

    Verify the output matches:

    ```
    -w /etc/group -p wa -k identity
    -w /etc/passwd -p wa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/security/opasswd -p wa -k identity
    -w /etc/nsswitch.conf -p wa -k identity
    -w /etc/pam.conf -p wa -k identity
    -w /etc/pam.d -p wa -k identity
    ```
  "
  desc  'fix', "
    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor events that modify user/group information.

    _Example:_

    ```
    # printf \"
    -w /etc/group -p wa -k identity
    -w /etc/passwd -p wa -k identity
    -w /etc/gshadow -p wa -k identity
    -w /etc/shadow -p wa -k identity
    -w /etc/security/opasswd -p wa -k identity
    -w /etc/nsswitch.conf -p wa -k identity
    -w /etc/pam.conf -p wa -k identity
    -w /etc/pam.d -p wa -k identity
    \" >> /etc/audit/rules.d/50-identity.rules
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
  tag nist:                  ['CM-7 a', 'AU-3 a']
  tag cci:                   ['CCI-000381', 'CCI-000130']
  tag cis_rid:               '6.3.3.8'
  tag cis_number:            '6.3.3.8'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030308r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grep -rhE -- '(\-k +identity|key=identity)' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end