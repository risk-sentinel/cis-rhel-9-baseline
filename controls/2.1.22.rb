# encoding: UTF-8

control 'C-2.1.22' do
  title 'Ensure only approved services are listening on a network interface'
  desc  "
    A network port is identified by its number, the associated IP address, and the type of the communication protocol such as TCP or UDP.

    A listening port is a network port on which an application or process listens on, acting as a communication endpoint.

    Each listening port can be open or closed (filtered) using a firewall. In general terms, an open port is a network port that accepts incoming packets from remote locations.

    Services listening on the system pose a potential risk as an attack vector.  These services should be reviewed, and if not required, the service should be stopped, and the package containing the service should be removed.  If required packages have a dependency, the service should be stopped and masked to reduce the attack surface of the system.
  "
  desc  'rationale', "
    A network port is identified by its number, the associated IP address, and the type of the communication protocol such as TCP or UDP.

    A listening port is a network port on which an application or process listens on, acting as a communication endpoint.

    Each listening port can be open or closed (filtered) using a firewall. In general terms, an open port is a network port that accepts incoming packets from remote locations.

    Services listening on the system pose a potential risk as an attack vector.  These services should be reviewed, and if not required, the service should be stopped, and the package containing the service should be removed.  If required packages have a dependency, the service should be stopped and masked to reduce the attack surface of the system.
  "
  desc  'check', "
    Run the following command:

    ```
    # ss -plntu
    ```

    Review the output to ensure:
    - All services listed are required on the system and approved by local site policy. 
    - Both the port and interface the service is listening on are approved by local site policy.
    - If a listed service is not required:
      - Remove the package containing the service
      - - IF - the service's package is required for a dependency, stop and mask the service and/or socket
  "
  desc  'fix', "
    Run the following commands to stop the service and remove the package containing the service:

    ```
    # systemctl stop .socket .service
    # dnf remove ```

    - OR - If required packages have a dependency:

    Run the following commands to stop and mask the service and socket:

    ```
    # systemctl stop .socket .service
    # systemctl mask .socket .service
    ```

    Note: replace ` ` with the appropriate service name.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.22'
  tag cis_number:            '2.1.22'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020122r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag exec_validated:        false
  tag attestation_category:  'operational'

  impact 0.5
  describe 'Approved listening services (2.1.22)' do
    skip 'manual/operational: the set of approved network-listening services is consumer-specific. Operator reviews `ss -plntu` against the approved-services baseline.'
  end
end