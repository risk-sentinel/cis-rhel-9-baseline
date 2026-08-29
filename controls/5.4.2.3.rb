# encoding: UTF-8

control 'C-5.4.2.3' do
  title 'Ensure group root is the only GID 0 group'
  desc  "
    The `groupmod` command can be used to specify which group the `root` group belongs to. This affects permissions of files that are group owned by the `root` group.

    Using GID 0 for the `root` group helps prevent `root` group owned files from accidentally becoming accessible to non-privileged users.
  "
  desc  'rationale', "
    The `groupmod` command can be used to specify which group the `root` group belongs to. This affects permissions of files that are group owned by the `root` group.

    Using GID 0 for the `root` group helps prevent `root` group owned files from accidentally becoming accessible to non-privileged users.
  "
  desc  'check', "
    Run the following command to verify no group other than `root` is assigned GID `0`:

    ```
    # awk -F: '$3==\"0\"{print $1\":\"$3}' /etc/group

    root:0
    ```
  "
  desc  'fix', "
    Run the following command to set the `root` group's GID to `0`:

    ```
    # groupmod -g 0 root
    ```

    Remove any groups other than the `root` group with GID 0 or assign them a new GID if appropriate.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.4.2.3'
  tag cis_number:            '5.4.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{awk -F: '($3==0 && $1!="root"){print $1}' /etc/group}) do
    its('stdout.strip') { should be_empty }
  end
end