# encoding: UTF-8

control 'C-2.1.15' do
  title 'Ensure telnet server services are not in use'
  desc  "
    The `telnet-server` package contains the `telnet` daemon, which accepts connections from users from other systems via the `telnet` protocol.

    The `telnet` protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The `ssh` package provides an encrypted session and stronger security.
  "
  desc  'rationale', "
    The `telnet-server` package contains the `telnet` daemon, which accepts connections from users from other systems via the `telnet` protocol.

    The `telnet` protocol is insecure and unencrypted. The use of an unencrypted transmission medium could allow a user with access to sniff network traffic the ability to steal credentials. The `ssh` package provides an encrypted session and stronger security.
  "
  desc  'check', "
    Run the following command to verify the `telnet-server` package is not installed:

    ```
    rpm -q telnet-server

    package telnet-server is not installed
    ```
    - OR -

    - IF - a package is installed and is required for dependencies:

    Run the following command to verify `telnet.socket` is not enabled:

    ```
    # systemctl is-enabled telnet.socket 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `telnet.socket` is not active:

    ```
    # systemctl is-active telnet.socket 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `telnet.socket` and remove the `telnet-server` package:

    ```
    # systemctl stop telnet.socket
    # dnf remove telnet-server
    ```

    - OR -

    - IF - a package is installed and is required for dependencies:

    Run the following commands to stop and mask `telnet.socket`:

    ```
    # systemctl stop telnet.socket
    # systemctl mask telnet.socket
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.15'
  tag cis_number:            '2.1.15'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020115r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure telnet server services are not in use' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-020115r1_rule.'
  end
end
