# encoding: UTF-8

control 'C-5.4.2.1' do
  title 'Ensure root is the only UID 0 account'
  desc  "
    Any account with UID 0 has superuser privileges on the system.

    This access must be limited to only the default `root` account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in the Recommendation \"Ensure access to the su command is restricted\".
  "
  desc  'rationale', "
    Any account with UID 0 has superuser privileges on the system.

    This access must be limited to only the default `root` account and only from the system console. Administrative access must be through an unprivileged account using an approved mechanism as noted in the Recommendation \"Ensure access to the su command is restricted\".
  "
  desc  'check', "
    Run the following command and verify that only \"root\" is returned:


    ```
    # awk -F: '($3 == 0) { print $1 }' /etc/passwd

    root
    ```
  "
  desc  'fix', "
    Run the following command to change the `root` account UID to `0`:

    ```
    # usermod -u 0 root
    ```

    Modify any users other than `root` with UID `0` and assign them a new UID.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.4.2.1'
  tag cis_number:            '5.4.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{awk -F: '($3==0){print $1}' /etc/passwd | grep -v '^root$'}) do
    its('stdout.strip') { should be_empty }
  end
end