# encoding: UTF-8

control 'C-2.2.3' do
  title 'Ensure nis client is not installed'
  desc  "
    The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client ( `ypbind` ) was used to bind a machine to an NIS server and receive the distributed configuration files.

    The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed.
  "
  desc  'rationale', "
    The Network Information Service (NIS), formerly known as Yellow Pages, is a client-server directory service protocol used to distribute system configuration files. The NIS client ( `ypbind` ) was used to bind a machine to an NIS server and receive the distributed configuration files.

    The NIS service is inherently an insecure system that has been vulnerable to DOS attacks, buffer overflows and has poor authentication for querying NIS maps. NIS generally has been replaced by such protocols as Lightweight Directory Access Protocol (LDAP). It is recommended that the service be removed.
  "
  desc  'check', "
    Run the following command to verify that the `ypbind` package is not installed:

    ```
    # rpm -q ypbind

    package ypbind is not installed
    ```
  "
  desc  'fix', "
    Run the following command to remove the ypbind package:

    ```
    # dnf remove ypbind
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.2.3'
  tag cis_number:            '2.2.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020203r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('ypbind') do
    it { should_not be_installed }
  end
end