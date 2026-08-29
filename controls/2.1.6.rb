# encoding: UTF-8

control 'C-2.1.6' do
  title 'Ensure samba file server services are not in use'
  desc  "
    The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Server Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.

    If there is no need to mount directories and file systems to Windows systems, then this package can be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    The Samba daemon allows system administrators to configure their Linux systems to share file systems and directories with Windows desktops. Samba will advertise the file systems and directories via the Server Message Block (SMB) protocol. Windows desktop users will be able to mount these directories and file systems as letter drives on their systems.

    If there is no need to mount directories and file systems to Windows systems, then this package can be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify `samba` package is not installed:

    ```
    # rpm -q samba

    package samba is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `smb.service` is not enabled:

    ```
    # systemctl is-enabled smb.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `smb.service` is not active:

    ```
    # systemctl is-active smb.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following command to stop `smb.service` and remove `samba` package:

    ```
    # systemctl stop smb.service
    # dnf remove samba
    ```

    - OR -

    - IF - the `samba` package is required as a dependency:

    Run the following commands to stop and mask the `smb.service`:

    ```
    # systemctl stop smb.service
    # systemctl mask smb.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.6'
  tag cis_number:            '2.1.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020106r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('smb') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end