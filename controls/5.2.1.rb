# encoding: UTF-8

control 'C-5.2.1' do
  title 'Ensure sudo is installed'
  desc  "
    `sudo` allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.  The invoking user's real (not effective) user ID is used to determine the user name with which to query the security policy.

    `sudo` supports a plug-in architecture for security policies and input/output logging.  Third parties can develop and distribute their own policy and I/O logging plug-ins to work seamlessly with the `sudo` front end. The default security policy is `sudoers`, which is configured via the file `/etc/sudoers` and any entries in `/etc/sudoers.d`.

    The security policy determines what privileges, if any, a user has to run `sudo`. The policy may require that users authenticate themselves with a password or another authentication mechanism. If authentication is required, `sudo` will exit if the user's password is not entered within a configurable time limit. This limit is policy-specific.
  "
  desc  'rationale', "
    `sudo` allows a permitted user to execute a command as the superuser or another user, as specified by the security policy.  The invoking user's real (not effective) user ID is used to determine the user name with which to query the security policy.

    `sudo` supports a plug-in architecture for security policies and input/output logging.  Third parties can develop and distribute their own policy and I/O logging plug-ins to work seamlessly with the `sudo` front end. The default security policy is `sudoers`, which is configured via the file `/etc/sudoers` and any entries in `/etc/sudoers.d`.

    The security policy determines what privileges, if any, a user has to run `sudo`. The policy may require that users authenticate themselves with a password or another authentication mechanism. If authentication is required, `sudo` will exit if the user's password is not entered within a configurable time limit. This limit is policy-specific.
  "
  desc  'check', "
    Verify that `sudo` is installed.

    Run the following command:

    ```
    # dnf list sudo

    Installed Packages
    sudo.x86_64 @anaconda
    Available Packages
    sudo.x86_64 updates
    ```
  "
  desc  'fix', "
    Run the following command to install sudo

    ```
    # dnf install sudo
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_rid:               '5.2.1'
  tag cis_number:            '5.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe package('sudo') do
    it { should be_installed }
  end
end