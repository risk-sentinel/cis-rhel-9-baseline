# encoding: UTF-8

control 'C-1.2.2.1' do
  title 'Ensure updates, patches, and additional security software are installed'
  desc  "
    Periodically patches are released for included software either due to security flaws or to include additional functionality.

    Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected.
  "
  desc  'rationale', "
    Periodically patches are released for included software either due to security flaws or to include additional functionality.

    Newer patches may contain security enhancements that would not be available through the latest full update. As a result, it is recommended that the latest software patches be used to take advantage of the latest functionality. As with any software installation, organizations need to determine if a given update meets their requirements and verify the compatibility and supportability of any additional software against the update revision that is selected.
  "
  desc  'check', "
    Run the following command and verify there are no updates or patches to install:

    ```
    # dnf check-update
    ```

    Check to make sure no system reboot is required

    ```
    dnf needs-restarting -r
    ```
  "
  desc  'fix', "
    Use your package manager to update all packages on the system according to site policy.

    The following command will install all available updates:

    ```
    # dnf update
    ```
    Once the update process is complete, verify if reboot is required to load changes.

    ```
    dnf needs-restarting -r
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-12', 'MP-6 a', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001028', 'CCI-001225']
  tag cis_rid:               '1.2.2.1'
  tag cis_number:            '1.2.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01020201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure updates, patches, and additional security software are installed' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-01020201r1_rule.'
  end
end
