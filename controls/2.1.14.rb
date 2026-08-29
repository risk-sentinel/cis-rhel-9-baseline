# encoding: UTF-8

control 'C-2.1.14' do
  title 'Ensure snmp services are not in use'
  desc  "
    Simple Network Management Protocol (SNMP) is a widely used protocol for monitoring the health and welfare of network equipment, computer equipment and devices like UPSs. 

    Net-SNMP is a suite of applications used to implement SNMPv1 (RFC 1157), SNMPv2 (RFCs 1901-1908), and SNMPv3 (RFCs 3411-3418) using both IPv4 and IPv6.  

    Support for SNMPv2 classic (a.k.a. \"SNMPv2 historic\" - RFCs 1441-1452) was dropped with the 4.0 release of the UCD-snmp package.

    The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.

    The SNMP server can communicate using `SNMPv1`, which transmits data in the clear and does not require authentication to execute commands. `SNMPv3` replaces the simple/clear text password sharing used in `SNMPv2` with more securely encoded parameters. If the the SNMP service is not required, the `net-snmp` package should be removed to reduce the attack surface of the system.

    Note: If SNMP is required:
    - The server should be configured for `SNMP v3` only. `User Authentication` and `Message Encryption` should be configured.
    - If `SNMP v2` is absolutely necessary, modify the community strings' values.
  "
  desc  'rationale', "
    Simple Network Management Protocol (SNMP) is a widely used protocol for monitoring the health and welfare of network equipment, computer equipment and devices like UPSs. 

    Net-SNMP is a suite of applications used to implement SNMPv1 (RFC 1157), SNMPv2 (RFCs 1901-1908), and SNMPv3 (RFCs 3411-3418) using both IPv4 and IPv6.  

    Support for SNMPv2 classic (a.k.a. \"SNMPv2 historic\" - RFCs 1441-1452) was dropped with the 4.0 release of the UCD-snmp package.

    The Simple Network Management Protocol (SNMP) server is used to listen for SNMP commands from an SNMP management system, execute the commands or collect the information and then send results back to the requesting system.

    The SNMP server can communicate using `SNMPv1`, which transmits data in the clear and does not require authentication to execute commands. `SNMPv3` replaces the simple/clear text password sharing used in `SNMPv2` with more securely encoded parameters. If the the SNMP service is not required, the `net-snmp` package should be removed to reduce the attack surface of the system.

    Note: If SNMP is required:
    - The server should be configured for `SNMP v3` only. `User Authentication` and `Message Encryption` should be configured.
    - If `SNMP v2` is absolutely necessary, modify the community strings' values.
  "
  desc  'check', "
    Run the following command to verify `net-snmp` package is not installed:

    ```
    # rpm -q net-snmp

    package net-snmp is not installed
    ```

    - OR - If the package is required for dependencies:

    Run the following command to verify the `snmpd.service` is not enabled:

    ```
    # systemctl is-enabled snmpd.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `snmpd.service` is not active:

    ```
    # systemctl is-active snmpd.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `snmpd.service` and remove `net-snmp` package:

    ```
    # systemctl stop snmpd.service
    # dnf remove net-snmp
    ```

    - OR - If the package is required for dependencies:

    Run the following commands to stop and mask the `snmpd.service`:

    ```
    # systemctl stop snmpd.service
    # systemctl mask snmpd.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.14'
  tag cis_number:            '2.1.14'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020114r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('snmpd') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end