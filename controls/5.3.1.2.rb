# encoding: UTF-8

control 'C-5.3.1.2' do
  title 'Ensure latest version of authselect is installed'
  desc  "
    Authselect is a utility that simplifies the configuration of user authentication. Authselect offers ready-made profiles that can be universally used with all modern identity management systems

    You can create and deploy a custom profile by customizing one of the default profiles, the sssd, winbind, or the nis profile. This is particularly useful if Modifying a ready-made authselect profile is not enough for your needs. When you deploy a custom profile, the profile is applied to every user logging into the given host. This would be the recommended method, so that the existing profiles can remain unmodified.

    Updated versions of `authselect` include additional functionality

    Authselect makes testing and troubleshooting easy because it only modifies files in these directories:
    - `/etc/nsswitch.conf`
    - `/etc/pam.d/*`
    - `/etc/dconf/db/distro.d/*`

    To ensure the system has full functionality and access to the options covered by this Benchmark, `authselect-1.2.6-2` or latter is required
  "
  desc  'rationale', "
    Authselect is a utility that simplifies the configuration of user authentication. Authselect offers ready-made profiles that can be universally used with all modern identity management systems

    You can create and deploy a custom profile by customizing one of the default profiles, the sssd, winbind, or the nis profile. This is particularly useful if Modifying a ready-made authselect profile is not enough for your needs. When you deploy a custom profile, the profile is applied to every user logging into the given host. This would be the recommended method, so that the existing profiles can remain unmodified.

    Updated versions of `authselect` include additional functionality

    Authselect makes testing and troubleshooting easy because it only modifies files in these directories:
    - `/etc/nsswitch.conf`
    - `/etc/pam.d/*`
    - `/etc/dconf/db/distro.d/*`

    To ensure the system has full functionality and access to the options covered by this Benchmark, `authselect-1.2.6-2` or latter is required
  "
  desc  'check', "
    Run the following command to verify the version of `authselect` on the system:

    ```
    # rpm -q authselect
    ```

    Verify output is version `authselect-1.2.6-2` or greater:

    _Example:_

    ```
    authselect-1.2.6-2.el9.x86_64
    ```
  "
  desc  'fix', "
    Run the following command to install `authselect`:

    ```
    # dnf install authselect
    ```

    - IF - the version of `authselect` on the system is less that version `authselect-1.2.6-2`:

    Run the following command to update to the latest version of `authselect`:

    ```
    # dnf upgrade authselect
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-6 b']
  tag cci:                   ['CCI-000366']
  tag cis_rid:               '5.3.1.2'
  tag cis_number:            '5.3.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('authselect') do
    it { should be_installed }
  end
end