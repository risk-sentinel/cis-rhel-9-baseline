# encoding: UTF-8

control 'C-1.2.1.2' do
  title 'Ensure gpgcheck is globally activated'
  desc  "
    The `gpgcheck` option, found in the main section of the `/etc/dnf/dnf.conf` and individual `/etc/yum.repos.d/*` files, determines if an RPM package's signature is checked prior to its installation.

    It is important to ensure that an RPM's package signature is always checked prior to installation to ensure that the software is obtained from a trusted source.
  "
  desc  'rationale', "
    The `gpgcheck` option, found in the main section of the `/etc/dnf/dnf.conf` and individual `/etc/yum.repos.d/*` files, determines if an RPM package's signature is checked prior to its installation.

    It is important to ensure that an RPM's package signature is always checked prior to installation to ensure that the software is obtained from a trusted source.
  "
  desc  'check', "
    Global configuration. Run the following command and verify that global configuration for `gpgcheck` is enabled. (set to `1`, `True`, or `yes`):

    ```
    # grep -Pi -- '^\\h*gpgcheck\\h*=\\h*(1|true|yes)\\b' /etc/dnf/dnf.conf

    gpgcheck=1
    ```

    Note: `true` or `yes` is also acceptable

    Configuration in `/etc/yum.repos.d/` takes precedence over the global configuration. Run the following command and verify that there are no instances of entries starting with `gpgcheck` returned set to `0`. Nor should there be any invalid (non-boolean) values. When `dnf` encounters such invalid entries they are ignored and the global configuration is applied.

    ```
    # grep -Pris -- '^\\h*gpgcheck\\h*=\\h*(0|[2-9]|[1-9][0-9]+|false|no)\\b' /etc/yum.repos.d/
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Edit `/etc/dnf/dnf.conf` and set `gpgcheck=1`:

    _Example_

    ```
    # sed -i 's/^gpgcheck\\s*=\\s*.*/gpgcheck=1/' /etc/dnf/dnf.conf
    ```

    Edit any failing files in `/etc/yum.repos.d/*` and set all instances starting with `gpgcheck` to `1`.

    _Example:_
    ```
    # find /etc/yum.repos.d/ -name \"*.repo\" -exec echo \"Checking:\" {} \\; -exec sed -i 's/^gpgcheck\\s*=\\s*.*/gpgcheck=1/' {} \\;
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['SI-12', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001225']
  tag cis_rid:               '1.2.1.2'
  tag cis_number:            '1.2.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01020102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -P -- '^\h*gpgcheck\h*=\h*1\b' /etc/dnf/dnf.conf}) do
    its('stdout') { should match(/\S/) }
  end
  describe command(%q{grep -rhP -- '^\h*gpgcheck\h*=' /etc/dnf/dnf.conf /etc/yum.repos.d/ 2>/dev/null | grep -vP -- '^\h*gpgcheck\h*=\h*1\b'}) do
    its('stdout.strip') { should be_empty }
  end
end