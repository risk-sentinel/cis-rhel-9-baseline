# encoding: UTF-8

control 'C-2.1.17' do
  title 'Ensure web proxy server services are not in use'
  desc  "
    Squid is a standard proxy server used in many distributions and environments.

    Unless a system is specifically set up to act as a proxy server, it is recommended that the squid package be removed to reduce the potential attack surface.

    Note: Several HTTP proxy servers exist. These should be checked and removed unless required.
  "
  desc  'rationale', "
    Squid is a standard proxy server used in many distributions and environments.

    Unless a system is specifically set up to act as a proxy server, it is recommended that the squid package be removed to reduce the potential attack surface.

    Note: Several HTTP proxy servers exist. These should be checked and removed unless required.
  "
  desc  'check', "
    Run the following command to verify `squid` package is not installed:

    ```
    # rpm -q squid

    package squid is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `squid.service` is not enabled:

    ```
    # systemctl is-enabled squid.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `squid.service` is not active:

    ```
    # systemctl is-active squid.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `squid.service` and remove the `squid` package:

    ```
    # systemctl stop squid.service
    # dnf remove squid
    ```

    - OR - If the `squid` package is required as a dependency:

    Run the following commands to stop and mask the `squid.service`:

    ```
    # systemctl stop squid.service
    # systemctl mask squid.service
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.17'
  tag cis_number:            '2.1.17'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020117r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure web proxy server services are not in use' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-020117r1_rule.'
  end
end
