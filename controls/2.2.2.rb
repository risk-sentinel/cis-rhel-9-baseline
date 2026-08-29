# encoding: UTF-8

control 'C-2.2.2' do
  title 'Ensure ldap client is not installed'
  desc  "
    The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.

    If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    The Lightweight Directory Access Protocol (LDAP) was introduced as a replacement for NIS/YP. It is a service that provides a method for looking up information from a central database.

    If the system will not need to act as an LDAP client, it is recommended that the software be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify that the `openldap-clients` package is not installed:

    ```
    # rpm -q openldap-clients

    package openldap-clients is not installed
    ```
  "
  desc  'fix', "
    Run the following command to remove the `openldap-clients` package:

    ```
    # dnf remove openldap-clients
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a']
  tag nist_r4:               ['CM-7 a']
  tag cci:                   ['CCI-000381']
  tag cis_rid:               '2.2.2'
  tag cis_number:            '2.2.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020202r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('openldap-clients') do
    it { should_not be_installed }
  end
end