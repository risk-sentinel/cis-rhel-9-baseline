# encoding: UTF-8

control 'C-2.3.3' do
  title 'Ensure chrony is not run as the root user'
  desc  "
    The file `/etc/sysconfig/chronyd` allows configuration of options for `chrony` to include the user `chrony` is run as.  By default, this is set to the user `chrony`

    Services should not be set to run as the root user
  "
  desc  'rationale', "
    The file `/etc/sysconfig/chronyd` allows configuration of options for `chrony` to include the user `chrony` is run as.  By default, this is set to the user `chrony`

    Services should not be set to run as the root user
  "
  desc  'check', "
    Run the following command to verify that `chrony` isn't configured to run as the `root` user:

    ```
    # grep -Psi -- '^\\h*OPTIONS=\\\"?\\h*([^#\\n\\r]+\\h+)?-u\\h+root\\b' /etc/sysconfig/chronyd

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Edit the file `/etc/sysconfig/chronyd` and add or modify the following line to remove \"`-u root`\" from any `OPTIONS=` argument:

    _Example:_
    ```
    OPTIONS=\"-F 2\"
    ```

    Run the following command to reload the `chronyd.service` configuration:

    ```
    # systemctl reload-or-restart chronyd.service
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '2.3.3'
  tag cis_number:            '2.3.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020303r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command("ps -eo user:32,comm | awk '$2==\"chronyd\"{print $1}' | sort -u") do
    its('stdout') { should_not match(/\broot\b/) }
  end
end