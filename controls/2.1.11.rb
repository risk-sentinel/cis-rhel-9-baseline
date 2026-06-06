# encoding: UTF-8

control 'C-2.1.11' do
  title 'Ensure print server services are not in use'
  desc  "
    The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.

    If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    The Common Unix Print System (CUPS) provides the ability to print to both local and network printers. A system running CUPS can also accept print jobs from remote systems and print them to local printers. It also provides a web based remote administration capability.

    If the system does not need to print jobs or accept print jobs from other systems, it is recommended that CUPS be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify `cups` is not installed:
    ```
    # rpm -q cups

    package cups is not installed
    ```

    - OR -

    - IF - the `cups` package is required as a dependency:

    Run the following command to verify the `cups.socket` and `cups.service` are not enabled:

    ```
    # systemctl is-enabled cups.socket cups.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `cups.socket` and `cups.service` are not active:

    ```
    # systemctl is-active cups.socket cups.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `cups.socket` and `cups.service`, and remove the `cups` package:

    ```
    # systemctl stop cups.socket cups.service
    # dnf remove cups
    ```

    - OR - 

    - IF - the `cups` package is required as a dependency:

    Run the following commands to stop and mask the `cups.socket` and `cups.service`:

    ```
    # systemctl stop cups.socket cups.service
    # systemctl mask cups.socket cups.service
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.11'
  tag cis_number:            '2.1.11'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020111r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe service('cups') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end