# encoding: UTF-8

control 'C-5.4.2.2' do
  title 'Ensure root is the only GID 0 account'
  desc  "
    The `usermod` command can be used to specify which group the `root` account belongs to. This affects permissions of files that are created by the `root` account.

    Using GID 0 for the `root` account helps prevent `root` -owned files from accidentally becoming accessible to non-privileged users.
  "
  desc  'rationale', "
    The `usermod` command can be used to specify which group the `root` account belongs to. This affects permissions of files that are created by the `root` account.

    Using GID 0 for the `root` account helps prevent `root` -owned files from accidentally becoming accessible to non-privileged users.
  "
  desc  'check', "
    Run the following command to verify the `root` user's primary GID is `0`, and no other user's have GID `0` as their primary GID:

    ```
    # awk -F: '($1 !~ /^(sync|shutdown|halt|operator)/ && $4==\"0\") {print $1\":\"$4}' /etc/passwd

    root:0
    ```

    Note: User's: sync, shutdown, halt, and operator are excluded from the check for other user's with GID `0`
  "
  desc  'fix', "
    Run the following command to set the `root` user's GID to `0`:

    ```
    # usermod -g 0 root
    ``` 

    Run the following command to set the `root` group's GID to `0`:

    ```
    # groupmod -g 0 root
    ```

    Remove any users other than the `root` user with GID 0 or assign them a new GID if appropriate.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.4.2.2'
  tag cis_number:            '5.4.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{awk -F: '($4==0 && $1!="root"){print $1}' /etc/passwd}) do
    its('stdout.strip') { should be_empty }
  end
end