# encoding: UTF-8

control 'C-5.2.5' do
  title 'Ensure re-authentication for privilege escalation is not disabled globally'
  desc  "
    The operating system must be configured so that users must re-authenticate for privilege escalation.

    Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

    When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.
  "
  desc  'rationale', "
    The operating system must be configured so that users must re-authenticate for privilege escalation.

    Without re-authentication, users may access resources or perform tasks for which they do not have authorization. 

    When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.
  "
  desc  'check', "
    Verify the operating system requires users to re-authenticate for privilege escalation.

    Check the configuration of the `/etc/sudoers` and `/etc/sudoers.d/*` files with the following command:

    ```
    # grep -r \"^[^#].*\\!authenticate\" /etc/sudoers*
    ```

    If any line is found with a `!authenticate` tag, refer to the remediation procedure below.
  "
  desc  'fix', "
    Configure the operating system to require users to reauthenticate for privilege escalation.

    Based on the outcome of the audit procedure, use `visudo -f ` to edit the relevant sudoers file.

    Remove any occurrences of `!authenticate` tags in the file(s).
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_rid:               '5.2.5'
  tag cis_number:            '5.2.5'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050205r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure re-authentication for privilege escalation is not disabled globally' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-050205r1_rule.'
  end
end
