# encoding: UTF-8

control 'C-6.3.1.3' do
  title 'Ensure audit_backlog_limit is sufficient'
  desc  "
    The `audit_backlog_limit` parameter determines how auditd records can be held in the auditd backlog. The default setting of 64 may be insufficient to store all audit events during boot.

    During boot if `audit=1`, then the backlog will hold 64 records.  If more than 64 records are created during boot, auditd records will be lost and potential malicious activity could go undetected.
  "
  desc  'rationale', "
    The `audit_backlog_limit` parameter determines how auditd records can be held in the auditd backlog. The default setting of 64 may be insufficient to store all audit events during boot.

    During boot if `audit=1`, then the backlog will hold 64 records.  If more than 64 records are created during boot, auditd records will be lost and potential malicious activity could go undetected.
  "
  desc  'check', "
    Note: `/etc/default/grub` should be checked because the `grub2-mkconfig -o` command will overwrite `grub.cfg` with parameters listed in `/etc/default/grub`.

    Run the following command and verify the `audit_backlog_limit=` parameter is set to an appropriate size for your organization

    ```
    # grubby --info=ALL | grep -Po \"\\baudit_backlog_limit=\\d+\\b\"

    audit_backlog_limit= ```

    Validate that the line(s) returned contain a value for `audit_backlog_limit=` that is sufficient for your organization.  

    Recommended that this value be `8192` or larger.

    Run the following command to verify that the `audit_backlog_limit= ` parameter has been set in `/etc/default/grub`:

    ```
    # grep -Psoi -- '^\\h*GRUB_CMDLINE_LINUX=\\\"([^#\\n\\r]+\\h+)?\\baudit_backlog_limit=\\d+\\b' /etc/default/grub
    ```

    _Example output:_

    ```
    GRUB_CMDLINE_LINUX=\"quiet audit_backlog_limit=8192\"
    ```

    Note: Other parameters may also be listed
  "
  desc  'fix', "
    Run the following command to add `audit_backlog_limit= ` to GRUB_CMDLINE_LINUX:

    ```
    # grubby --update-kernel ALL --args 'audit_backlog_limit= '
    ```

    _Example:_
    ```
    # grubby --update-kernel ALL --args 'audit_backlog_limit=8192'
    ```

    Edit `/etc/default/grub` and add `audit_backlog_limit= ` to the `GRUB_CMDLINE_LINUX=` line between the opening and closing double quotes:

    _Example:_

    ```
    GRUB_CMDLINE_LINUX=\"quiet audit_backlog_limit=8192\"
    ```

    Note: Other parameters may also be listed
  "
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-2 a']
  tag cci:                   ['CCI-000011', 'CCI-000123']
  tag cis_rid:               '6.3.1.3'
  tag cis_number:            '6.3.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe command(%q{grubby --info=ALL 2>/dev/null | grep '^args=' | grep -v 'audit_backlog_limit='}) do
    its('stdout.strip') { should be_empty }
  end
end