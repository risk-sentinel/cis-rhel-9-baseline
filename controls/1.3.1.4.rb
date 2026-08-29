# encoding: UTF-8

control 'C-1.3.1.4' do
  title 'Ensure the SELinux mode is not disabled'
  desc  "
    SELinux can run in one of three modes: disabled, permissive, or enforcing:
    - `Enforcing` - Is the default, and recommended, mode of operation; in enforcing mode SELinux operates normally, enforcing the loaded security policy on the entire system.
    - `Permissive` - The system acts as if SELinux is enforcing the loaded security policy, including labeling objects and emitting access denial entries in the logs, but it does not actually deny any operations. While not recommended for production systems, permissive mode can be helpful for SELinux policy development.
    - `Disabled` - Is strongly discouraged; not only does the system avoid enforcing the SELinux policy, it also avoids labeling any persistent objects such as files, making it difficult to enable SELinux in the future

    Note: You can set individual domains to permissive mode while the system runs in enforcing mode. For example, to make the httpd_t domain permissive:

    ```
    # semanage permissive -a httpd_t
    ```

    Running SELinux in disabled mode is strongly discouraged; not only does the system avoid enforcing the SELinux policy, it also avoids labeling any persistent objects such as files, making it difficult to enable SELinux in the future.
  "
  desc  'rationale', "
    SELinux can run in one of three modes: disabled, permissive, or enforcing:
    - `Enforcing` - Is the default, and recommended, mode of operation; in enforcing mode SELinux operates normally, enforcing the loaded security policy on the entire system.
    - `Permissive` - The system acts as if SELinux is enforcing the loaded security policy, including labeling objects and emitting access denial entries in the logs, but it does not actually deny any operations. While not recommended for production systems, permissive mode can be helpful for SELinux policy development.
    - `Disabled` - Is strongly discouraged; not only does the system avoid enforcing the SELinux policy, it also avoids labeling any persistent objects such as files, making it difficult to enable SELinux in the future

    Note: You can set individual domains to permissive mode while the system runs in enforcing mode. For example, to make the httpd_t domain permissive:

    ```
    # semanage permissive -a httpd_t
    ```

    Running SELinux in disabled mode is strongly discouraged; not only does the system avoid enforcing the SELinux policy, it also avoids labeling any persistent objects such as files, making it difficult to enable SELinux in the future.
  "
  desc  'check', "
    Run the following command to verify SELinux's current mode:
    ```
    # getenforce

    Enforcing
    -OR-
    Permissive
    ```

    Run the following command to verify SELinux's configured mode:

    ```
    # grep -Ei '^\\s*SELINUX=(enforcing|permissive)' /etc/selinux/config

    SELINUX=enforcing
    -OR-
    SELINUX=permissive
    ```
  "
  desc  'fix', "
    Run one of the following commands to set SELinux's running mode:

    To set SELinux mode to `Enforcing`:
    ```
    # setenforce 1
    ```

    - OR -

    To set SELinux mode to `Permissive`:
    ```
    # setenforce 0
    ```

    Edit the `/etc/selinux/config` file to set the SELINUX parameter:

    For Enforcing mode:
    ```
    SELINUX=enforcing
    ```

    - OR -

    For Permissive mode:
    ```
    SELINUX=permissive
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.3.1.4'
  tag cis_number:            '1.3.1.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01030104r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe selinux do
    it { should_not be_disabled }
  end
end