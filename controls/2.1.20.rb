# encoding: UTF-8

control 'C-2.1.20' do
  title 'Ensure X window server services are not in use'
  desc  "
    The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.

    Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface.
  "
  desc  'rationale', "
    The X Window System provides a Graphical User Interface (GUI) where users can have multiple windows in which to run programs and various add on. The X Windows system is typically used on workstations where users login, but not on servers where users typically do not login.

    Unless your organization specifically requires graphical login access via X Windows, remove it to reduce the potential attack surface.
  "
  desc  'check', "
    - IF - a Graphical Desktop Manager or X-Windows server is not required and approved by local site policy:

    Run the following command to Verify X Windows Server is not installed.

    ```
    # rpm -q xorg-x11-server-common

    package xorg-x11-server-common is not installed
    ```
  "
  desc  'fix', "
    - IF - a Graphical Desktop Manager or X-Windows server is not required and approved by local site policy:

    Run the following command to remove the X Windows Server packages:

    ```
    # dnf remove xorg-x11-server-common
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.20'
  tag cis_number:            '2.1.20'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020120r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('xorg-x11-server-common') do
    it { should_not be_installed }
  end
end