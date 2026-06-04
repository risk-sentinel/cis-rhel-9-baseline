# encoding: UTF-8

control 'C-2.1.12' do
  title 'Ensure rpcbind services are not in use'
  desc  "
    The `rpcbind` utility maps RPC services to the ports on which they listen. RPC processes notify `rpcbind` when they start, registering the ports they are listening on and the RPC program numbers they expect to serve. The client system then contacts `rpcbind` on the server with a particular RPC program number. The `rpcbind.service` redirects the client to the proper port number so it can communicate with the requested service.

    Portmapper is an RPC service, which always listens on tcp and udp 111, and is used to map other RPC services (such as nfs, nlockmgr, quotad, mountd, etc.) to their corresponding port number on the server. When a remote host makes an RPC call to that server, it first consults with portmap to determine where the RPC server is listening.

    A small request (~82 bytes via UDP) sent to the Portmapper generates a large response (7x to 28x amplification), which makes it a suitable tool for DDoS attacks. If `rpcbind` is not required, it is recommended to remove `rpcbind` package to reduce the potential attack surface.
  "
  desc  'rationale', "
    The `rpcbind` utility maps RPC services to the ports on which they listen. RPC processes notify `rpcbind` when they start, registering the ports they are listening on and the RPC program numbers they expect to serve. The client system then contacts `rpcbind` on the server with a particular RPC program number. The `rpcbind.service` redirects the client to the proper port number so it can communicate with the requested service.

    Portmapper is an RPC service, which always listens on tcp and udp 111, and is used to map other RPC services (such as nfs, nlockmgr, quotad, mountd, etc.) to their corresponding port number on the server. When a remote host makes an RPC call to that server, it first consults with portmap to determine where the RPC server is listening.

    A small request (~82 bytes via UDP) sent to the Portmapper generates a large response (7x to 28x amplification), which makes it a suitable tool for DDoS attacks. If `rpcbind` is not required, it is recommended to remove `rpcbind` package to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify `rpcbind` package is not installed:

    ```
    # rpm -q rpcbind

    package rpcbind is not installed
    ```

    - OR - 

    - IF - the `rpcbind` package is required as a dependency:

    Run the following command to verify `rpcbind.socket` and `rpcbind.service` are not enabled:

    ```
    # systemctl is-enabled rpcbind.socket rpcbind.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `rpcbind.socket` and `rpcbind.service` are not active:

    ```
    # systemctl is-active rpcbind.socket rpcbind.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `rpcbind.socket` and `rpcbind.service`, and remove the `rpcbind` package:

    ```
    # systemctl stop rpcbind.socket rpcbind.service
    # dnf remove rpcbind
    ```

    - OR -

    - IF - the `rpcbind` package is required as a dependency:

    Run the following commands to stop and mask the `rpcbind.socket` and `rpcbind.service`:

    ```
    # systemctl stop rpcbind.socket rpcbind.service
    # systemctl mask rpcbind.socket rpcbind.service
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.12'
  tag cis_number:            '2.1.12'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020112r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure rpcbind services are not in use' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-020112r1_rule.'
  end
end
