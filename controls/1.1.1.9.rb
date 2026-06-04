# encoding: UTF-8

control 'C-1.1.1.9' do
  title 'Ensure unused filesystems kernel modules are not available'
  desc  "
    Filesystem kernel modules are pieces of code that can be dynamically loaded into the Linux kernel to extend its filesystem capabilities, or so-called base kernel, of an operating system. Filesystem kernel modules are typically used to add support for new hardware (as device drivers), or for adding system calls.

    While loadable filesystem kernel modules are a convenient method of modifying the running kernel, this can be abused by attackers on a compromised system to prevent detection of their processes or files, allowing them to maintain control over the system. Many rootkits make use of loadable filesystem kernel modules in this way. 

    Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it. The following filesystem kernel modules have known CVE's and should be made unavailable if no dependencies exist:
    - `afs` - CVE-2022-37402
    - `ceph` - CVE-2022-0670
    - `cifs` - CVE-2022-29869 
    - `exfat` CVE-2022-29973 
    - `ext` CVE-2022-1184
    - `fat` CVE-2022-22043
    - `fscache` CVE-2022-3630 
    - `fuse` CVE-2023-0386 
    - `gfs2` CVE-2023-3212
    - `nfs_common` CVE-2023-6660
    - `nfsd` CVE-2022-43945
    - `smbfs_common` CVE-2022-2585
  "
  desc  'rationale', "
    Filesystem kernel modules are pieces of code that can be dynamically loaded into the Linux kernel to extend its filesystem capabilities, or so-called base kernel, of an operating system. Filesystem kernel modules are typically used to add support for new hardware (as device drivers), or for adding system calls.

    While loadable filesystem kernel modules are a convenient method of modifying the running kernel, this can be abused by attackers on a compromised system to prevent detection of their processes or files, allowing them to maintain control over the system. Many rootkits make use of loadable filesystem kernel modules in this way. 

    Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it. The following filesystem kernel modules have known CVE's and should be made unavailable if no dependencies exist:
    - `afs` - CVE-2022-37402
    - `ceph` - CVE-2022-0670
    - `cifs` - CVE-2022-29869 
    - `exfat` CVE-2022-29973 
    - `ext` CVE-2022-1184
    - `fat` CVE-2022-22043
    - `fscache` CVE-2022-3630 
    - `fuse` CVE-2023-0386 
    - `gfs2` CVE-2023-3212
    - `nfs_common` CVE-2023-6660
    - `nfsd` CVE-2022-43945
    - `smbfs_common` CVE-2022-2585
  "
  desc  'check', "
    Run the following script to:
    - Look at the filesystem kernel modules available to the currently running kernel.
    - Exclude mounted filesystem kernel modules that don't currently have a CVE
    - List filesystem kernel modules that are not fully disabled, or are loaded into the kernel

    Review the generated output

    ``` 
    #! /usr/bin/env bash

    {
       a_output=(); a_output2=(); a_modprope_config=(); a_excluded=(); a_available_modules=()
       a_ignore=(\"xfs\" \"vfat\" \"ext2\" \"ext3\" \"ext4\")
       a_cve_exists=(\"afs\" \"ceph\" \"cifs\" \"exfat\" \"ext\" \"fat\" \"fscache\" \"fuse\" \"gfs2\" \"nfs_common\" \"nfsd\" \"smbfs_common\")
       f_module_chk()
       {
          l_out2=\"\"; grep -Pq -- \"\\b$l_mod_name\\b\" <<< \"${a_cve_exists[*]}\" && l_out2=\" <- CVE exists!\"
          if ! grep -Pq -- '\\bblacklist\\h+'\"$l_mod_name\"'\\b' <<< \"${a_modprope_config[*]}\"; then
             a_output2+=(\"  - Kernel module: \\\"$l_mod_name\\\" is not fully disabled $l_out2\")
          elif ! grep -Pq -- '\\binstall\\h+'\"$l_mod_name\"'\\h+\\/bin\\/(false|true)\\b' <<< \"${a_modprope_config[*]}\"; then
             a_output2+=(\"  - Kernel module: \\\"$l_mod_name\\\" is not fully disabled $l_out2\")
          fi
          if lsmod | grep \"$l_mod_name\" &> /dev/null; then # Check if the module is currently loaded
             l_output2+=(\"  - Kernel module: \\\"$l_mod_name\\\" is loaded\" \"\")
          fi
       }
       while IFS= read -r -d $'\\0' l_module_dir; do
          a_available_modules+=(\"$(basename \"$l_module_dir\")\")
       done < <(find \"$(readlink -f /lib/modules/\"$(uname -r)\"/kernel/fs)\" -mindepth 1 -maxdepth 1 -type d ! -empty -print0)
       while IFS= read -r l_exclude; do
          if grep -Pq -- \"\\b$l_exclude\\b\" <<< \"${a_cve_exists[*]}\"; then
             a_output2+=(\"  -  WARNING: kernel module: \\\"$l_exclude\\\" has a CVE and is currently mounted! \")
          elif 
             grep -Pq -- \"\\b$l_exclude\\b\" <<< \"${a_available_modules[*]}\"; then
             a_output+=(\"  - Kernel module: \\\"$l_exclude\\\" is currently mounted - do NOT unload or disable\")
          fi
          ! grep -Pq -- \"\\b$l_exclude\\b\" <<< \"${a_ignore[*]}\" && a_ignore+=(\"$l_exclude\")
       done < <(findmnt -knD | awk '{print $2}' | sort -u)
       while IFS= read -r l_config; do
          a_modprope_config+=(\"$l_config\")
       done < <(modprobe --showconfig | grep -P '^\\h*(blacklist|install)')
       for l_mod_name in \"${a_available_modules[@]}\"; do # Iterate over all filesystem modules
          [[ \"$l_mod_name\" =~ overlay ]] && l_mod_name=\"${l_mod_name::-2}\"
          if grep -Pq -- \"\\b$l_mod_name\\b\" <<< \"${a_ignore[*]}\"; then
             a_excluded+=(\" - Kernel module: \\\"$l_mod_name\\\"\")
          else
             f_module_chk
          fi
       done
       [ \"${#a_excluded[@]}\" -gt 0 ] && printf '%s\\n' \"\" \" -- INFO --\" \\
       \"The following intentionally skipped\" \\
        \"${a_excluded[@]}\"
       if [ \"${#a_output2[@]}\" -le 0 ]; then
          printf '%s\\n' \"\" \"  - No unused filesystem kernel modules are enabled\" \"${a_output[@]}\" \"\"
       else
          printf '%s\\n' \"\" \"-- Audit Result: --\" \"   REVIEW the following \" \"${a_output2[@]}\"
          [ \"${#a_output[@]}\" -gt 0 ] && printf '%s\\n' \"\" \"-- Correctly set: --\" \"${a_output[@]}\" \"\"
       fi
    }
    ``` 
	
    WARNING: disabling or denylisting filesystem modules that are in use on the system may be FATAL. It is extremely important to thoroughly review this list.
  "
  desc  'fix', "
    - IF - the module is available in the running kernel:
    - Unload the filesystem kernel module from the kernel
    - Create a file ending in `.conf` with install filesystem kernel modules `/bin/false` in the `/etc/modprobe.d/` directory
    - Create a file ending in `.conf` with deny list filesystem kernel modules in the `/etc/modprobe.d/` directory

    WARNING: unloading, disabling or denylisting filesystem modules that are in use on the system maybe FATAL. It is extremely important to thoroughly review the filesystems returned by the audit before following the remediation procedure.

    _Example of unloading the `gfs2`kernel module:_

    ```
    # modprobe -r gfs2 2>/dev/null
    # rmmod gfs2 2>/dev/null
    ```

    _Example of fully disabling the `gfs2` kernel module:_

    ```
    # printf '%s\\n' \"blacklist gfs2\" \"install gfs2 /bin/false\" >> /etc/modprobe.d/gfs2.conf
    ```

    Note: 
    - Disabling a kernel module by modifying the command above for each unused filesystem kernel module
    - The example `gfs2` must be updated with the appropriate module name for the command or example script bellow to run correctly.

    Below is an example Script that can be modified to use on various filesystem kernel modules manual remediation process:

    _Example Script_

    ```
    #!/usr/bin/env bash

    {
       unset a_output2; l_output3=\"\" l_dl=\"\" # unset arrays and clear variables
       l_mod_name=\"gfs2\" # set module name
       l_mod_type=\"fs\" # set module type
       l_mod_path=\"$(readlink -f /lib/modules//kernel/$l_mod_type | sort -u)\"
       f_module_fix()
       {
          l_dl=\"y\" # Set to ignore duplicate checks
          a_showconfig=() # Create array with modprobe output
          while IFS= read -r l_showconfig; do
             a_showconfig+=(\"$l_showconfig\")
          done < <(modprobe --showconfig | grep -P -- '\\b(install|blacklist)\\h+'\"${l_mod_name//-/_}\"'\\b')
          if  lsmod | grep \"$l_mod_name\" &> /dev/null; then # Check if the module is currently loaded
             a_output2+=(\" - unloading kernel module: \\\"$l_mod_name\\\"\")
             modprobe -r \"$l_mod_name\" 2>/dev/null; rmmod \"$l_mod_name\" 2>/dev/null
          fi
          if ! grep -Pq -- '\\binstall\\h+'\"${l_mod_name//-/_}\"'\\h+\\/bin\\/(true|false)\\b' <<< \"${a_showconfig[*]}\"; then
             a_output2+=(\" - setting kernel  module: \\\"$l_mod_name\\\" to \\\"/bin/false\\\"\")
             printf '%s\\n' \"install $l_mod_name /bin/false\" >> /etc/modprobe.d/\"$l_mod_name\".conf
          fi
          if ! grep -Pq -- '\\bblacklist\\h+'\"${l_mod_name//-/_}\"'\\b' <<< \"${a_showconfig[*]}\"; then
             a_output2+=(\" - denylisting kernel  module: \\\"$l_mod_name\\\"\")
             printf '%s\\n' \"blacklist $l_mod_name\" >> /etc/modprobe.d/\"$l_mod_name\".conf
          fi
       }
       for l_mod_base_directory in $l_mod_path; do # Check if the module exists on the system
          if [ -d \"$l_mod_base_directory/${l_mod_name/-/\\/}\" ] && [ -n \"$(ls -A $l_mod_base_directory/${l_mod_name/-/\\/})\" ]; then
             l_output3=\"$l_output3\\n  - \\\"$l_mod_base_directory\\\"\"
             [[ \"$l_mod_name\" =~ overlay ]] && l_mod_name=\"${l_mod_name::-2}\"        
             [ \"$l_dl\" != \"y\" ] && f_module_fix
          else
             echo -e \" - kernel module: \\\"$l_mod_name\\\" doesn't exist in \\\"$l_mod_base_directory\\\"\"
          fi
       done
       [ -n \"$l_output3\" ] && echo -e \"\\n\\n -- INFO --\\n - module: \\\"$l_mod_name\\\" exists in:$l_output3\"
       [ \"${#a_output2[@]}\" -gt 0 ] && printf '%s\\n' \"${a_output2[@]}\"
       echo -e \"\\n - remediation of kernel module: \\\"$l_mod_name\\\" complete\\n\"
    }
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.1.1.9'
  tag cis_number:            '1.1.1.9'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01010109r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true

  describe 'Ensure unused filesystems kernel modules are not available' do
    skip 'TODO[scaffolder]: implement check against XCCDF check-content. Source rule SV-01010109r1_rule.'
  end
end
