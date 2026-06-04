# encoding: UTF-8

control 'C-1.8.1' do
  title 'Ensure GNOME Display Manager is removed'
  desc  "
    The GNOME Display Manager (GDM) is a program that manages graphical display servers and handles graphical user logins.

    If a Graphical User Interface (GUI) is not required, it should be removed to reduce the attack surface of the system.
  "
  desc  'rationale', "
    The GNOME Display Manager (GDM) is a program that manages graphical display servers and handles graphical user logins.

    If a Graphical User Interface (GUI) is not required, it should be removed to reduce the attack surface of the system.
  "
  desc  'check', "
    Run the following command and verify the output:

    ```
    # rpm -q gdm

    package gdm is not installed
    ```
  "
  desc  'fix', "
    Run the following command to remove the `gdm` package

    ```
    # dnf remove gdm
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.8.1'
  tag cis_number:            '1.8.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010801r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure GNOME Display Manager is removed' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-010801r1_rule.'
  end
end
