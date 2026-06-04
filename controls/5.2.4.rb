# encoding: UTF-8

control 'C-5.2.4' do
  title 'Ensure users must provide password for escalation'
  desc  "
    The operating system must be configured so that users must provide a password for privilege escalation.

    Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

    When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.
  "
  desc  'rationale', "
    The operating system must be configured so that users must provide a password for privilege escalation.

    Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

    When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.
  "
  desc  'check', "
    Note: If passwords are not being used for authentication, this is not applicable.

    Verify the operating system requires users to supply a password for privilege escalation.

    Check the configuration of the `/etc/sudoers` and `/etc/sudoers.d/*` files with the following command:

    ```
    # grep -r \"^[^#].*NOPASSWD\" /etc/sudoers*
    ```

    If any line is found refer to the remediation procedure below.
  "
  desc  'fix', "
    Based on the outcome of the audit procedure, use `visudo -f ` to edit the relevant sudoers file.

    Remove any line with occurrences of `NOPASSWD` tags in the file.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_rid:               '5.2.4'
  tag cis_number:            '5.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure users must provide password for escalation' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-050204r1_rule.'
  end
end
