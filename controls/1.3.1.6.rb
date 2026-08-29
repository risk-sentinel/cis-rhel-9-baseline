# encoding: UTF-8

control 'C-1.3.1.6' do
  title 'Ensure no unconfined services exist'
  desc  "
    Unconfined processes run in unconfined domains

    For unconfined processes, SELinux policy rules are applied, but policy rules exist that allow processes running in unconfined domains almost all access. Processes running in unconfined domains fall back to using DAC rules exclusively. If an unconfined process is compromised, SELinux does not prevent an attacker from gaining access to system resources and data, but of course, DAC rules are still used. SELinux is a security enhancement on top of DAC rules - it does not replace them
  "
  desc  'rationale', "
    Unconfined processes run in unconfined domains

    For unconfined processes, SELinux policy rules are applied, but policy rules exist that allow processes running in unconfined domains almost all access. Processes running in unconfined domains fall back to using DAC rules exclusively. If an unconfined process is compromised, SELinux does not prevent an attacker from gaining access to system resources and data, but of course, DAC rules are still used. SELinux is a security enhancement on top of DAC rules - it does not replace them
  "
  desc  'check', "
    Run the following command and verify no output is produced:

    ```
    # ps -eZ | grep unconfined_service_t
    ```
  "
  desc  'fix', "
    Investigate any unconfined processes found during the audit action. If necessary create a customize SELinux policy to allow necessary actions for the service.

    Warning: Knowledge about creating and configuring SELinux policies is needed. A Basic example on how to create a policy is included below.

    1. Identify the unconfined service: determine the name and process of the service
 
    2. Identify the functionality: determine if the functionality is required for operations

    3. Create or add to the custom allow list in the SELinux policy configuration

    _Example SELinux policy configuration: service_allowlist_policy.te_

    ```
    # Example SELinux policy configuration for allowing access to specific actions and resources for a service

    module my_service 1.0;

    require {
        type my_service_t;
        type system_resource_t;
        class file { read write execute };
        class dir { read write add_name };
        class tcp_socket name_connect;
    }

    allow my_service_t system_resource_t:file { read write execute }; # Allow my_service_t to read, write, and execute files with the system_resource_t context

    allow my_service_t system_resource_t:dir { read write add_name }; # Allow my_service_t to read and write to directories with the system_resource_t context

    allow my_service_t system_resource_t:tcp_socket name_connect; # Allow my_service_t to establish TCP connections
    ```

    4. Compile the policy
    ```
    # checkmodule -M -, -o service_allowlist_policy.mod service_allowlist_policy.te
    ```

    5. Create the package
    ```
    # semodule_package -o service_allowlist_policy.pp -m service_allowlist_policy.mod
    ```

    6. Load the policy
    ```
    # semodule -i service_allowlist_policy.pp
    ```

    7. Apply the policy to the service
    ```
    # chcon -t se service_allowlist_policy /path/to/service_binary
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'SI-4 (11)']
  tag cci:                   ['CCI-000213', 'CCI-002668']
  tag cis_rid:               '1.3.1.6'
  tag cis_number:            '1.3.1.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01030106r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{ps -eZ 2>/dev/null | grep unconfined_service_t | grep -v -E 'bash|ps |grep'}) do
    its('stdout.strip') { should be_empty }
  end
end