# encoding: UTF-8

control 'C-7.2.1' do
  title 'Ensure accounts in /etc/passwd use shadowed passwords'
  desc  "
    Local accounts can uses shadowed passwords.  With shadowed passwords, The passwords are saved in shadow password file, `/etc/shadow`, encrypted by a salted one-way hash. Accounts with a shadowed password have an `x` in the second field in `/etc/passwd`.

    The `/etc/passwd` file also contains information like user ID's and group ID's that are used by many system programs. Therefore, the `/etc/passwd` file must remain world readable. In spite of encoding the password with a randomly-generated one-way hash function, an attacker could still break the system if they got access to the `/etc/passwd` file. This can be mitigated by using shadowed passwords, thus moving the passwords in the `/etc/passwd` file to `/etc/shadow`. The `/etc/shadow` file is set so only root will be able to read and write. This helps mitigate the risk of an attacker gaining access to the encoded passwords with which to perform a dictionary attack.  

    Note:
    - All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
    - A user account with an empty second field in `/etc/passwd` allows the account to be logged into by providing only the username.
  "
  desc  'rationale', "
    Local accounts can uses shadowed passwords.  With shadowed passwords, The passwords are saved in shadow password file, `/etc/shadow`, encrypted by a salted one-way hash. Accounts with a shadowed password have an `x` in the second field in `/etc/passwd`.

    The `/etc/passwd` file also contains information like user ID's and group ID's that are used by many system programs. Therefore, the `/etc/passwd` file must remain world readable. In spite of encoding the password with a randomly-generated one-way hash function, an attacker could still break the system if they got access to the `/etc/passwd` file. This can be mitigated by using shadowed passwords, thus moving the passwords in the `/etc/passwd` file to `/etc/shadow`. The `/etc/shadow` file is set so only root will be able to read and write. This helps mitigate the risk of an attacker gaining access to the encoded passwords with which to perform a dictionary attack.  

    Note:
    - All accounts must have passwords or be locked to prevent the account from being used by an unauthorized user.
    - A user account with an empty second field in `/etc/passwd` allows the account to be logged into by providing only the username.
  "
  desc  'check', "
    Run the following command and verify that no output is returned:

    ```
    # awk -F: '($2 != \"x\" ) { print \"User: \\\"\" $1 \"\\\" is not set to shadowed passwords \"}' /etc/passwd
    ```
  "
  desc  'fix', "
    Run the following command to set accounts to use shadowed passwords and migrate passwords in `/etc/passwd` to `/etc/shadow`:

    ```
    # pwconv
    ```

    Investigate to determine if the account is logged in and what it is being used for, to determine if it needs to be forced off.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SC-28', 'CM-8 a 1']
  tag ksi:                   ['KSI-PIY-GIV', 'KSI-SVC-SIN']
  tag nist_r4:               ['CM-8 a 1', 'SC-28']
  tag cci:                   ['CCI-001199', 'CCI-000389']
  tag cis_rid:               '7.2.1'
  tag cis_number:            '7.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-070201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{awk -F: '($2 != "x") {print $1}' /etc/passwd}) do
    its('stdout') { should be_empty }
  end
end