# encoding: UTF-8

control 'C-2.1.10' do
  title 'Ensure nis server services are not in use'
  desc  "
    The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client ( `ypbind` ) was used to bind a machine to an NIS server and receive the distributed configuration files.

    The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed.
  "
  desc  'rationale', "
    The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client ( `ypbind` ) was used to bind a machine to an NIS server and receive the distributed configuration files.

    The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed.
  "
  desc  'check', "
    Run the following command to verify `ypserv` is not installed:

    ```
    # rpm -q ypserv

    package ypserv is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `ypserv.service` is not enabled:

    ```
    # systemctl is-enabled ypserv.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `ypserv.service` is not active:

    ```
    # systemctl is-active ypserv.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `ypserv.service` and remove `ypserv` package:

    ```
    # systemctl stop ypserv.service
    # dnf remove ypserv
    ```

    - OR -

    - IF - the `ypserv` package is required as a dependency:

    Run the following commands to stop and mask `ypserv.service`:

    ```
    # systemctl stop ypserv.service
    # systemctl mask ypserv.service
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.10'
  tag cis_number:            '2.1.10'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020110r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('ypserv') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end