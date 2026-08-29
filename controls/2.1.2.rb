# encoding: UTF-8

control 'C-2.1.2' do
  title 'Ensure avahi daemon services are not in use'
  desc  "
    Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.

    Automatic discovery of network services is not normally required for system functionality. It is recommended to remove this package to reduce the potential attack surface.
  "
  desc  'rationale', "
    Avahi is a free zeroconf implementation, including a system for multicast DNS/DNS-SD service discovery. Avahi allows programs to publish and discover services and hosts running on a local network with no specific configuration. For example, a user can plug a computer into a network and Avahi automatically finds printers to print to, files to look at and people to talk to, as well as network services running on the machine.

    Automatic discovery of network services is not normally required for system functionality. It is recommended to remove this package to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify the `avahi` package is not installed:

    ```
    # rpm -q avahi

    package avahi is not installed
    ```

    - OR - 

    - IF - the `avahi` package is required as a dependency:

    Run the following command to verify `avahi-daemon.socket` and `avahi-daemon.service` are not enabled:

    ```
    # systemctl is-enabled avahi-daemon.socket avahi-daemon.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `avahi-daemon.socket` and `avahi-daemon.service` are not active:

    ```
    # systemctl is-active avahi-daemon.socket avahi-daemon.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `avahi-daemon.socket` and `avahi-daemon.service`, and remove the `avahi` package:

    ```
    # systemctl stop avahi-daemon.socket avahi-daemon.service
    # dnf remove avahi
    ```

    - OR -

    - IF - the `avahi` package is required as a dependency:

    Run the following commands to stop and mask the `avahi-daemon.socket` and `avahi-daemon.service`:

    ```
    # systemctl stop avahi-daemon.socket avahi-daemon.service
    # systemctl mask avahi-daemon.socket avahi-daemon.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.2'
  tag cis_number:            '2.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('avahi-daemon') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
  describe service('avahi-daemon.socket') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end