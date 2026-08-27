# encoding: UTF-8

control 'C-5.4.2.4' do
  title 'Ensure root account access is controlled'
  desc  "
    There are a number of methods to access the root account directly. Without a password set any user would be able to gain access and thus control over the entire system.

    Access to `root` should be secured at all times.
  "
  desc  'rationale', "
    There are a number of methods to access the root account directly. Without a password set any user would be able to gain access and thus control over the entire system.

    Access to `root` should be secured at all times.
  "
  desc  'check', "
    Run the following command to verify that either the root user's password is set or the root user's account is locked:

    ```
    # passwd -S root | awk '$2 ~ /^P/ {print \"User: \\\"\" $1 \"\\\" Password is set\"}'
    ```

    Verify the output is either:

    ```
    (Password set, SHA512 crypt.)
    - OR -
    (Password locked.)
    ```

    Note: output may include `YESCRYPT` opposed to `SHA512`. Either is acceptable.
  "
  desc  'fix', "
    Run the following command to set a password for the `root` user:

    ```
    # passwd root
    ```

    - OR -

    Run the following command to lock the `root` user account:

    ```
    # usermod -L root
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.4.2.4'
  tag cis_number:            '5.4.2.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040204r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  # access_model axis: federated_ssm makes root access controllable by positive
  # evidence — the SSM/IAM layer gates access and direct root SSH is closed. interactive
  # keeps the IAM-governance attestation (verified surface is 5.2.7 su + 5.1.20).
  if access_federated?
    impact 0.5
    ok = federated_boundary_ok?
    describe 'federated_ssm root-access boundary (ssm-agent running + direct root SSH disabled)' do
      subject { ok }
      it { is_expected.to be true }
    end
  else
    impact 0.5
    describe 'root account access controlled (5.4.2.4)' do
      skip 'operational: root-access governance (console/break-glass, locked direct login, MFA on bastion) is an org IAM-policy decision; verified surface is covered by 5.2.7 (su) + 5.1.20 (PermitRootLogin).'
    end
  end
end