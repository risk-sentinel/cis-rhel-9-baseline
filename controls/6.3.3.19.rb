# encoding: UTF-8

control 'C-6.3.3.19' do
  title 'Ensure kernel module loading unloading and modification is collected'
  desc  "
    Monitor the loading and unloading of kernel modules. All the loading / listing / dependency checking of modules is done by `kmod` via symbolic links.

    The following system calls control loading and unloading of modules:
    - `init_module` - load a module
    - `finit_module` - load a module (used when the overhead of using cryptographically signed modules to determine the authenticity of a module can be avoided)
    - `delete_module` - delete a module
    - `create_module` - create a loadable module entry
    - `query_module` - query the kernel for various bits pertaining to modules

    Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of `modules`.

    Monitoring the use of all the various ways to manipulate kernel modules could provide system administrators with evidence that an unauthorized change was made to a kernel module, possibly compromising the security of the system.
  "
  desc  'rationale', "
    Monitor the loading and unloading of kernel modules. All the loading / listing / dependency checking of modules is done by `kmod` via symbolic links.

    The following system calls control loading and unloading of modules:
    - `init_module` - load a module
    - `finit_module` - load a module (used when the overhead of using cryptographically signed modules to determine the authenticity of a module can be avoided)
    - `delete_module` - delete a module
    - `create_module` - create a loadable module entry
    - `query_module` - query the kernel for various bits pertaining to modules

    Any execution of the loading and unloading module programs and system calls will trigger an audit record with an identifier of `modules`.

    Monitoring the use of all the various ways to manipulate kernel modules could provide system administrators with evidence that an unauthorized change was made to a kernel module, possibly compromising the security of the system.
  "
  desc  'check', "
    On disk configuration

    Run the following script to check the on disk rules:

    ```
    #!/usr/bin/env bash

    {
      awk '/^ *-a *always,exit/ \\
      &&/ -F *arch=b(32|64)/ \\
      &&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) \\
      &&/ -S/ \\
      &&(/init_module/ \\
        ||/finit_module/ \\
        ||/delete_module/ \\
        ||/create_module/ \\
        ||/query_module/) \\
      &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)' /etc/audit/rules.d/*.rules

      UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
      [ -n \"${UID_MIN}\" ] && awk \"/^ *-a *always,exit/ \\
      &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
      &&/ -F *auid>=${UID_MIN}/ \\
      &&/ -F *perm=x/ \\
      &&/ -F *path=\\/usr\\/bin\\/kmod/ \\
      &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" /etc/audit/rules.d/*.rules \\
      || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output matches:

    ```
    -a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=1000 -F auid!=unset -k kernel_modules
    -a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=unset -k kernel_modules
    ```

    Running configuration

    Run the following script to check loaded rules:

    ```
    #!/usr/bin/env bash

    {
      auditctl -l | awk '/^ *-a *always,exit/ \\
      &&/ -F *arch=b(32|64)/ \\
      &&(/ -F auid!=unset/||/ -F auid!=-1/||/ -F auid!=4294967295/) \\
      &&/ -S/ \\
      &&(/init_module/ \\
        ||/finit_module/ \\
        ||/delete_module/ \\
        ||/create_module/ \\
        ||/query_module/) \\
      &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)'

      UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
      [ -n \"${UID_MIN}\" ] && auditctl -l | awk \"/^ *-a *always,exit/ \\
      &&(/ -F *auid!=unset/||/ -F *auid!=-1/||/ -F *auid!=4294967295/) \\
      &&/ -F *auid>=${UID_MIN}/ \\
      &&/ -F *perm=x/ \\
      &&/ -F *path=\\/usr\\/bin\\/kmod/ \\
      &&(/ key= *[!-~]* *$/||/ -k *[!-~]* *$/)\" \\
      || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Verify the output includes:

    ```
    -a always,exit -F arch=b64 -S create_module,init_module,delete_module,query_module,finit_module -F auid>=1000 -F auid!=-1 -F key=kernel_modules
    -a always,exit -S all -F path=/usr/bin/kmod -F perm=x -F auid>=1000 -F auid!=-1 -F key=kernel_modules
    ```

    Symlink audit

    Run the following script to audit if the symlinks `kmod` accepts are indeed pointing at it:

    ```
    #!/usr/bin/env bash

    {
       a_files=(\"/usr/sbin/lsmod\" \"/usr/sbin/rmmod\" \"/usr/sbin/insmod\" \"/usr/sbin/modinfo\" \"/usr/sbin/modprobe\" \"/usr/sbin/depmod\")
       for l_file in \"${a_files[@]}\"; do
          if [ \"$(readlink -f \"$l_file\")\" = \"$(readlink -f /bin/kmod)\" ]; then
             printf \"OK: \\\"$l_file\\\"\\n\"
          else
             printf \"Issue with symlink for file: \\\"$l_file\\\"\\n\"
          fi
       done
    }
    ```

    Verify the output states `OK`. If there is a symlink pointing to a different location it should be investigated
  "
  desc  'fix', "
    Create audit rules

    Edit or create a file in the `/etc/audit/rules.d/` directory, ending in `.rules` extension, with the relevant rules to monitor kernel module modification.

    _Example:_

    ```
    #!/usr/bin/env bash

    {
      UID_MIN=$(awk '/^\\s*UID_MIN/{print $2}' /etc/login.defs)
      [ -n \"${UID_MIN}\" ] && printf \"
      -a always,exit -F arch=b64 -S init_module,finit_module,delete_module,create_module,query_module -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
      -a always,exit -F path=/usr/bin/kmod -F perm=x -F auid>=${UID_MIN} -F auid!=unset -k kernel_modules
      \" >> /etc/audit/rules.d/50-kernel_modules.rules || printf \"ERROR: Variable 'UID_MIN' is unset.\\n\"
    }
    ```

    Load audit rules

    Merge and load the rules into active configuration:

    ```
    # augenrules --load
    ```

    Check if reboot is required.

    ```
    # if [[ $(auditctl -s | grep \"enabled\") =~ \"2\" ]]; then printf \"Reboot required to load rules\\n\"; fi
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['AC-2 f', 'AU-3 a']
  tag cci:                   ['CCI-000011', 'CCI-000130']
  tag cis_rid:               '6.3.3.19'
  tag cis_number:            '6.3.3.19'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-06030319r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rhE -- '(init_module|finit_module|delete_module|create_module|\-k +(modules|kernel_modules)|key=(modules|kernel_modules))' /etc/audit/rules.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end