# encoding: UTF-8

control 'C-1.3.1.3' do
  title 'Ensure SELinux policy is configured'
  desc  "
    Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.

    Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met.
  "
  desc  'rationale', "
    Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.

    Security configuration requirements vary from site to site. Some sites may mandate a policy that is stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that at least the default recommendations are met.
  "
  desc  'check', "
    Run the following commands and ensure output matches either \" `targeted` \" or \" `mls` \":

    ```
    # grep -E '^\\s*SELINUXTYPE=(targeted|mls)\\b' /etc/selinux/config

    SELINUXTYPE=targeted
    ```

    ```
    # sestatus | grep Loaded

    Loaded policy name:             targeted
    ```
  "
  desc  'fix', "
    Edit the `/etc/selinux/config` file to set the SELINUXTYPE parameter:

    ```
    SELINUXTYPE=targeted
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.3.1.3'
  tag cis_number:            '1.3.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01030103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -E '^\s*SELINUXTYPE=(targeted|mls)' /etc/selinux/config}) do
    its('stdout') { should match(/\S/) }
  end
end