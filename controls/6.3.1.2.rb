# encoding: UTF-8

control 'C-6.3.1.2' do
  title 'Ensure auditing for processes that start prior to auditd is enabled'
  desc  "
    Configure `grub2` so that processes that are capable of being audited can be audited even if they start up prior to `auditd` startup.

    Audit events need to be captured on processes that start up prior to `auditd` , so that potential malicious activity cannot go undetected.
  "
  desc  'rationale', "
    Configure `grub2` so that processes that are capable of being audited can be audited even if they start up prior to `auditd` startup.

    Audit events need to be captured on processes that start up prior to `auditd` , so that potential malicious activity cannot go undetected.
  "
  desc  'check', "
    Note: `/etc/default/grub` should be checked because the `grub2-mkconfig -o` command will overwrite `grub.cfg` with parameters listed in `/etc/default/grub`.

    Run the following command to verify that the `audit=1` parameter has been set:

    ```
    # grubby --info=ALL | grep -Po '\\baudit=1\\b'

    audit=1
    ```

    Note: `audit=1` may be returned multiple times

    Run the following command to verify that the `audit=1` parameter has been set in `/etc/default/grub`:

    ```
    # grep -Psoi -- '^\\h*GRUB_CMDLINE_LINUX=\\\"([^#\\n\\r]+\\h+)?audit=1\\b' /etc/default/grub
    ```

    _Example output:_

    ```
    GRUB_CMDLINE_LINUX=\"quiet audit=1\"
    ```

    Note: Other parameters may also be listed
  "
  desc  'fix', "
    Run the following command to update the `grub2` configuration with `audit=1`:

    ```
    # grubby --update-kernel ALL --args 'audit=1'
    ```

    Edit `/etc/default/grub` and add `audit=1` to the `GRUB_CMDLINE_LINUX=` line between the opening and closing double quotes:

    _Example:_

    ```
    GRUB_CMDLINE_LINUX=\"quiet audit=1\"
    ```

    Note: Other parameters may also be listed
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_rid:               '6.3.1.2'
  tag cis_number:            '6.3.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true
  impact 0.5
  describe command(%q{grubby --info=ALL 2>/dev/null | grep '^args=' | grep -v 'audit=1'}) do
    its('stdout.strip') { should be_empty }
  end
end