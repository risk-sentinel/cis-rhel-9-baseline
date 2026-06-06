# encoding: UTF-8

control 'C-2.1.16' do
  title 'Ensure tftp server services are not in use'
  desc  "
    Trivial File Transfer Protocol (TFTP) is a simple protocol for exchanging files between two TCP/IP machines. TFTP servers allow connections from a TFTP Client for sending and receiving files.

    Unless there is a need to run the system as a TFTP server, it is recommended that the package be removed to reduce the potential attack surface.

    TFTP does not have built-in encryption, access control or authentication. This makes it very easy for an attacker to exploit TFTP to gain access to files
  "
  desc  'rationale', "
    Trivial File Transfer Protocol (TFTP) is a simple protocol for exchanging files between two TCP/IP machines. TFTP servers allow connections from a TFTP Client for sending and receiving files.

    Unless there is a need to run the system as a TFTP server, it is recommended that the package be removed to reduce the potential attack surface.

    TFTP does not have built-in encryption, access control or authentication. This makes it very easy for an attacker to exploit TFTP to gain access to files
  "
  desc  'check', "
    Run the following command to verify `tftp-server` is not installed:

    ```
    # rpm -q tftp-server

    package tftp-server is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `tftp.socket` and  `tftp.service` are not enabled:

    ```
    # systemctl is-enabled tftp.socket tftp.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `tftp.socket` and `tftp.service` are not active:

    ```
    # systemctl is-active tftp.socket tftp.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `tftp.socket` and `tftp.service`, and remove the `tftp-server` package:

    ```
    # systemctl stop tftp.socket tftp.service
    # dnf remove tftp-server
    ```

    - OR -

    - IF - the `tftp-server` package is required as a dependency:

    Run the following commands to stop and mask `tftp.socket` and `tftp.service`:

    ```
    # systemctl stop tftp.socket tftp.service
    # systemctl mask tftp.socket tftp.service
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.16'
  tag cis_number:            '2.1.16'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020116r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe service('tftp.socket') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end