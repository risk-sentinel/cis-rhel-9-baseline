# encoding: UTF-8

control 'C-2.1.7' do
  title 'Ensure ftp server services are not in use'
  desc  "
    FTP (File Transfer Protocol) is a traditional and widely used standard tool for transferring files between a server and clients over a network, especially where no authentication is necessary (permits anonymous users to connect to a server).

    Unless there is a need to run the system as a FTP server, it is recommended that the package be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    FTP (File Transfer Protocol) is a traditional and widely used standard tool for transferring files between a server and clients over a network, especially where no authentication is necessary (permits anonymous users to connect to a server).

    Unless there is a need to run the system as a FTP server, it is recommended that the package be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify `vsftpd` is not installed:

    ```
    # rpm -q vsftpd

    package vsftpd is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `vsftpd` service is not enabled:

    ```
    # systemctl is-enabled vsftpd.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `vsftpd` service is not active:

    ```
    # systemctl is-active vsftpd.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: 
    - Other ftp server packages may exist. They should also be audited, if not required and authorized by local site policy
     - If the package is required for a dependency:
       - Ensure the dependent package is approved by local site policy
       - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `vsftpd.service` and remove `vsftpd` package:

    ```
    # systemctl stop vsftpd.service
    # dnf remove vsftpd
    ```

    - OR -

    - IF - the `vsftpd` package is required as a dependency:

    Run the following commands to stop and mask the `vsftpd.service`:

    ```
    # systemctl stop vsftpd.service
    # systemctl mask vsftpd.service
    ```

    Note: Other ftp server packages may exist. If not required and authorized by local site policy, they should also be removed. If the package is required for a dependency, the service should be stopped and masked.
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.7'
  tag cis_number:            '2.1.7'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020107r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('vsftpd') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end