# encoding: UTF-8

control 'C-2.2.1' do
  title 'Ensure ftp client is not installed'
  desc  "
    FTP (File Transfer Protocol) is a traditional and widely used standard tool for transferring files between a server and clients over a network, especially where no authentication is necessary (permits anonymous users to connect to a server).

    FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    FTP (File Transfer Protocol) is a traditional and widely used standard tool for transferring files between a server and clients over a network, especially where no authentication is necessary (permits anonymous users to connect to a server).

    FTP does not protect the confidentiality of data or authentication credentials. It is recommended SFTP be used if file transfer is required. Unless there is a need to run the system as a FTP server (for example, to allow anonymous downloads), it is recommended that the package be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify `ftp` is not installed:

    ```
    # rpm -q ftp

    package ftp is not installed
    ```
  "
  desc  'fix', "
    Run the following command to remove `ftp`:

    ```
    # dnf remove ftp
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.2.1'
  tag cis_number:            '2.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure ftp client is not installed' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-020201r1_rule.'
  end
end
