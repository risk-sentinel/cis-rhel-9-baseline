# encoding: UTF-8

control 'C-2.1.18' do
  title 'Ensure web server services are not in use'
  desc  "
    Web servers provide the ability to host web site content.

    Unless there is a local site approved requirement to run a web server service on the system, web server packages should be removed to reduce the potential attack surface.
  "
  desc  'rationale', "
    Web servers provide the ability to host web site content.

    Unless there is a local site approved requirement to run a web server service on the system, web server packages should be removed to reduce the potential attack surface.
  "
  desc  'check', "
    Run the following command to verify `httpd` and `nginx` are not installed:

    ```
    # rpm -q httpd nginx

    package httpd is not installed
    package nginx is not installed
    ```
    - OR -

    - IF - a package is installed and is required for dependencies:

    Run the following command to verify `httpd.socket`, `httpd.service`, and `nginx.service` are not enabled:

    ```
    # systemctl is-enabled httpd.socket httpd.service nginx.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `httpd.socket`, `httpd.service`, and `nginx.service` are not active:

    ```
    # systemctl is-active httpd.socket httpd.service nginx.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: 
    - Other web server packages may exist. They should also be audited, if not required and authorized by local site policy
     - If the package is required for a dependency:
       - Ensure the dependent package is approved by local site policy
       - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `httpd.socket`, `httpd.service`, and `nginx.service`, and remove `httpd` and `nginx` packages:

    ```
    # systemctl stop httpd.socket httpd.service nginx.service
    # dnf remove httpd nginx
    ```

    - OR -

    - IF - a package is installed and is required for dependencies:

    Run the following commands to stop and mask `httpd.socket`, `httpd.service`, and `nginx.service`:

    ```
    # systemctl stop httpd.socket httpd.service nginx.service
    # systemctl mask httpd.socket httpd.service nginx.service
    ```

    Note: Other web server packages may exist. If not required and authorized by local site policy, they should also be removed. If the package is required for a dependency, the service and socket should be stopped and masked.
  "
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '2.1.18'
  tag cis_number:            '2.1.18'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-020118r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('httpd') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
  describe service('nginx') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end