# encoding: UTF-8

control 'C-2.1.1' do
  title 'Ensure autofs services are not in use'
  desc  "
    `autofs` allows automatic mounting of devices, typically including CD/DVDs and USB drives.

    With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves.
  "
  desc  'rationale', "
    `autofs` allows automatic mounting of devices, typically including CD/DVDs and USB drives.

    With automounting enabled anyone with physical access could attach a USB drive or disc and have its contents available in system even if they lacked permissions to mount it themselves.
  "
  desc  'check', "
    As a preference `autofs` should not be installed unless other packages depend on it.

    Run the following command to verify `autofs` is not installed:

    ```
    # rpm -q autofs

    package autofs is not installed
    ```

    - OR - 

    - IF - the package is required for dependencies:

    Run the following command to verify `autofs.service` is not enabled:

    ```
    # systemctl is-enabled autofs.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify the `autofs.service` is not active:

    ```
    # systemctl is-active autofs.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `autofs.service` and remove `autofs` package:

    ```
    # systemctl stop autofs.service
    # dnf remove autofs
    ```

    - OR -

    - IF - the `autofs` package is required as a dependency:

    Run the following commands to stop and mask `autofs.service`:

    ```
    # systemctl stop autofs.service
    # systemctl mask autofs.service
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AU-3 a', 'MP-7 (a)']
  tag ksi:                   ['KSI-MLA-OSM']
  tag nist_r4:               ['AU-3', 'MP-7']
  tag cci:                   ['CCI-000130', 'CCI-002581']
  tag cis_rid:               '2.1.1'
  tag cis_number:            '2.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('autofs') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end