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
  tag implementation_status: 'implemented'

  # access_model axis (#4): interactive requires a sudo password; federated_ssm gates
  # access/escalation at the IAM/SSM layer, so NOPASSWD is acceptable ONLY while the
  # boundary holds (ssm-agent running + direct root SSH disabled) — assert that boundary.
  if access_federated?
    impact 0.5
    ok = federated_boundary_ok?
    describe 'federated_ssm access boundary (ssm-agent running + direct root SSH disabled)' do
      subject { ok }
      it { is_expected.to be true }
    end
  else
    impact 0.5
    describe command(%q{grep -rP -- '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null}) do
      its('stdout.strip') { should be_empty }
    end
  end
end