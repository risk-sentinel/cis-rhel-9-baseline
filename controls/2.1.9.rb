# encoding: UTF-8

control 'C-2.1.9' do
  title 'Ensure network file system services are not in use'
  desc  "
    The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.

    If the system does not require access to network shares or the ability to provide network file system services for other host's network shares, it is recommended that the `nfs-utils` package be removed to reduce the attack surface of the system.
  "
  desc  'rationale', "
    The Network File System (NFS) is one of the first and most widely distributed file systems in the UNIX environment. It provides the ability for systems to mount file systems of other servers through the network.

    If the system does not require access to network shares or the ability to provide network file system services for other host's network shares, it is recommended that the `nfs-utils` package be removed to reduce the attack surface of the system.
  "
  desc  'check', "
    Run the following command to verify `nfs-utils` is not installed:

    ```
    # rpm -q nfs-utils

    package nfs-utils is not installed
    ```

    - OR - If package is required for dependencies: 

    Run the following command to verify that the `nfs-server.service` is not enabled:

    ```
    # systemctl is-enabled nfs-server.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `nfs-server.service` is not active:

    ```
    # systemctl is-active nfs-server.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following command to stop `nfs-server.service` and remove `nfs-utils` package:
    ```
    # systemctl stop nfs-server.service
    # dnf remove nfs-utils
    ```

    - OR -

    - IF - the `nfs-utils` package is required as a dependency:

    Run the following commands to stop and mask the `nfs-server.service`:

    ```
    # systemctl stop nfs-server.service
    # systemctl mask nfs-server.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.9'
  tag cis_number:            '2.1.9'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020109r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('nfs-server') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end