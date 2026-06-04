# encoding: UTF-8

control 'C-2.1.19' do
  title 'Ensure xinetd services are not in use'
  desc  "
    The eXtended InterNET Daemon (`xinetd`) is an open source super daemon that replaced the original `inetd` daemon. The `xinetd` daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.

    If there are no `xinetd` services required, it is recommended that the package be removed to reduce the attack surface are of the system.

    Note: If an `xinetd` service or services are required, ensure that any `xinetd` service not required is stopped and masked
  "
  desc  'rationale', "
    The eXtended InterNET Daemon (`xinetd`) is an open source super daemon that replaced the original `inetd` daemon. The `xinetd` daemon listens for well known services and dispatches the appropriate daemon to properly respond to service requests.

    If there are no `xinetd` services required, it is recommended that the package be removed to reduce the attack surface are of the system.

    Note: If an `xinetd` service or services are required, ensure that any `xinetd` service not required is stopped and masked
  "
  desc  'check', "
    Run the following command to verify the `xinetd` package is not installed:

    ```
    # rpm -q xinetd

    package xinetd is not installed
    ```

    - OR - 

    - IF - the `xinetd` package is required as a dependency:

    Run the following command to verify `xinetd.service` is not enabled:

    ```
    # systemctl is-enabled xinetd.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `xinetd.service` is not active:

    ```
    # systemctl is-active xinetd.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `xinetd.service`, and remove the `xinetd` package:

    ```
    # systemctl stop xinetd.service
    # dnf remove xinetd
    ```

    - OR -

    - IF - the `xinetd` package is required as a dependency:

    Run the following commands to stop and mask the `xinetd.service`:

    ```
    # systemctl stop xinetd.service
    # systemctl mask xinetd.service
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.19'
  tag cis_number:            '2.1.19'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020119r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('xinetd') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end