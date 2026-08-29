# encoding: UTF-8

control 'C-2.1.13' do
  title 'Ensure rsync services are not in use'
  desc  "
    The `rsyncd.service` can be used to synchronize files between systems over network links.

    Unless required, the `rsync-daemon` package should be removed to reduce the potential attack surface.

    The `rsyncd.service` presents a security risk as it uses unencrypted protocols for communication.
  "
  desc  'rationale', "
    The `rsyncd.service` can be used to synchronize files between systems over network links.

    Unless required, the `rsync-daemon` package should be removed to reduce the potential attack surface.

    The `rsyncd.service` presents a security risk as it uses unencrypted protocols for communication.
  "
  desc  'check', "
    Run the following command to verify the `rsync-daemon` package is not installed:

    ```
    # rpm -q rsync-daemon

    package rsync-daemon is not installed
    ```

    - OR - 

    - IF - the `rsync-daemon` package is required as a dependency:

    Run the following command to verify `rsyncd.socket` and `rsyncd.service` are not enabled:

    ```
    # systemctl is-enabled rsyncd.socket rsyncd.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `rsyncd.socket` and `rsyncd.service` are not active:

    ```
    # systemctl is-active rsyncd.socket rsyncd.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `rsyncd.socket` and `rsyncd.service`, and remove the `rsync-daemon` package:

    ```
    # systemctl stop rsyncd.socket rsyncd.service
    # dnf remove rsync-daemon
    ```

    - OR -

    - IF - the `rsync-daemon` package is required as a dependency:

    Run the following commands to stop and mask the `rsyncd.socket` and `rsyncd.service`:

    ```
    # systemctl stop rsyncd.socket rsyncd.service
    # systemctl mask rsyncd.socket rsyncd.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.13'
  tag cis_number:            '2.1.13'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020113r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('rsyncd') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end