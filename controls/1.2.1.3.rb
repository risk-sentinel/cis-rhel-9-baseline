# encoding: UTF-8

control 'C-1.2.1.3' do
  title 'Ensure repo_gpgcheck is globally activated'
  desc  "
    The `repo_gpgcheck` option, found in the main section of the `/etc/dnf/dnf.conf` and individual `/etc/yum.repos.d/*` files, will perform a GPG signature check on the repodata.

    It is important to ensure that the repository data signature is always checked prior to installation to ensure that the software is not tampered with in any way.
  "
  desc  'rationale', "
    The `repo_gpgcheck` option, found in the main section of the `/etc/dnf/dnf.conf` and individual `/etc/yum.repos.d/*` files, will perform a GPG signature check on the repodata.

    It is important to ensure that the repository data signature is always checked prior to installation to ensure that the software is not tampered with in any way.
  "
  desc  'check', "
    Global configuration

    Run the following command:

    ```
    grep ^repo_gpgcheck /etc/dnf/dnf.conf
    ```

    Verify that `repo_gpgcheck` is set to `1`

    Per repository configuration

    Configuration in `/etc/yum.repos.d/` takes precedence over the global configuration.

    As an example, to list all the configured repositories, excluding \"fedoraproject.org\", that specifically disables `repo_gpgcheck`, run the following command:

    ```
    # REPO_URL=\"fedoraproject.org\"
    # for repo in $(grep -l \"repo_gpgcheck=0\" /etc/yum.repos.d/* ); do
      if ! grep \"${REPO_URL}\" \"${repo}\" &>/dev/null; then
        echo \"${repo}\"
      fi
    done
    ```

    Per the research that was done on which repositories does not support `repo_gpgcheck`, change the `REPO_URL` variable and run the test.
  "
  desc  'fix', "
    Global configuration

    Edit `/etc/dnf/dnf.conf` and set `repo_gpgcheck=1` in the `[main]` section.

    _Example:_

    ```
    [main]
    repo_gpgcheck=1
    ```

    Per repository configuration

    First check that the particular repository support GPG checking on the repodata.

    Edit any failing files in `/etc/yum.repos.d/*` and set all instances starting with `repo_gpgcheck` to `1`.
  "
  tag severity:              'medium'
  tag nist:                  ['SI-12', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001225']
  tag cis_rid:               '1.2.1.3'
  tag cis_number:            '1.2.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01020103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -P -- '^\h*repo_gpgcheck\h*=\h*1\b' /etc/dnf/dnf.conf}) do
    its('stdout') { should match(/\S/) }
  end
end