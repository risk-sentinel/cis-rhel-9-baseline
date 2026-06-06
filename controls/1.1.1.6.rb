# encoding: UTF-8

control 'C-1.1.1.6' do
  title 'Ensure squashfs kernel module is not available'
  desc  "
    The `squashfs` filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A `squashfs` image can be used without having to first decompress the image.

    Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  desc  'rationale', "
    The `squashfs` filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems. A `squashfs` image can be used without having to first decompress the image.

    Removing support for unneeded filesystem types reduces the local attack surface of the system. If this filesystem type is not needed, disable it.
  "
  desc  'check', "
    Run the following script to verify:

    - IF - the `squashfs` kernel module is available in ANY installed kernel, verify:
    - An entry including `/bin/true` or `/bin/false` exists in a file within the `/etc/modprobe.d/` directory
    - The module is deny listed in a file within the `/etc/modprobe.d/` directory
    - The module is not loaded in the running kernel

    - IF - the `squashfs` kernel module is not available on the system, or pre-compiled into the kernel, no additional configuration is necessary

    ```
    #!/usr/bin/env bash

    {
       l_output3=\"\" l_dl=\"\" # clear variables
       unset a_output; unset a_output2 # unset arrays
       l_mod_name=\"squashfs\" # set module name
       l_mod_type=\"fs\" # set module type
       l_mod_path=\"$(readlink -f /lib/modules//kernel/$l_mod_type | sort -u)\"
       f_module_chk()
       {
          l_dl=\"y\" # Set to ignore duplicate checks
          a_showconfig=() # Create array with modprobe output
          while IFS= read -r l_showconfig; do
             a_showconfig+=(\"$l_showconfig\")
          done < <(modprobe --showconfig | grep -P -- '\\b(install|blacklist)\\h+'\"${l_mod_name//-/_}\"'\\b')
          if ! lsmod | grep \"$l_mod_name\" &> /dev/null; then # Check if the module is currently loaded
             a_output+=(\"  - kernel module: \\\"$l_mod_name\\\" is not loaded\")
          else
             a_output2+=(\"  - kernel module: \\\"$l_mod_name\\\" is loaded\")
          fi
          if grep -Pq -- '\\binstall\\h+'\"${l_mod_name//-/_}\"'\\h+\\/bin\\/(true|false)\\b' <<< \"${a_showconfig[*]}\"; then
             a_output+=(\"  - kernel module: \\\"$l_mod_name\\\" is not loadable\")
          else
             a_output2+=(\"  - kernel module: \\\"$l_mod_name\\\" is loadable\")
          fi
          if grep -Pq -- '\\bblacklist\\h+'\"${l_mod_name//-/_}\"'\\b' <<< \"${a_showconfig[*]}\"; then
             a_output+=(\"  - kernel module: \\\"$l_mod_name\\\" is deny listed\")
          else
             a_output2+=(\"  - kernel module: \\\"$l_mod_name\\\" is not deny listed\")
          fi
       }
       for l_mod_base_directory in $l_mod_path; do # Check if the module exists on the system
          if [ -d \"$l_mod_base_directory/${l_mod_name/-/\\/}\" ] && [ -n \"$(ls -A $l_mod_base_directory/${l_mod_name/-/\\/})\" ]; then
             l_output3=\"$l_output3\\n  - \\\"$l_mod_base_directory\\\"\"
             [[ \"$l_mod_name\" =~ overlay ]] && l_mod_name=\"${l_mod_name::-2}\"        
             [ \"$l_dl\" != \"y\" ] && f_module_chk
          else
             a_output+=(\" - kernel module: \\\"$l_mod_name\\\" doesn't exist in \\\"$l_mod_base_directory\\\"\")
          fi
       done
       [ -n \"$l_output3\" ] && echo -e \"\\n\\n -- INFO --\\n - module: \\\"$l_mod_name\\\" exists in:$l_output3\"
       if [ \"${#a_output2[@]}\" -le 0 ]; then
          printf '%s\\n' \"\" \"- Audit Result:\" \"   PASS \" \"${a_output[@]}\"
       else
          printf '%s\\n' \"\" \"- Audit Result:\" \"   FAIL \" \" - Reason(s) for audit failure:\" \"${a_output2[@]}\"
          [ \"${#a_output[@]}\" -gt 0 ] && printf '%s\\n' \"- Correctly set:\" \"${a_output[@]}\"
       fi
    }
    ```

    Note: On operating systems where `squashfs` is pre-build into the kernel:
    - This is considered an acceptable \"passing\" state
    - The kernel should not be re-compiled to remove `squashfs`
    - This audit will return a passing state with \"module: \"squashfs\" doesn't exist in ...\"
  "
  desc  'fix', "
    Run the following script to unload and disable the `udf` module:

    - IF - the `squashfs` kernel module is available in ANY installed kernel:
     - Create a file ending in `.conf` with `install squashfs /bin/false` in the `/etc/modprobe.d/` directory
     - Create a file ending in `.conf` with `blacklist squashfs` in the `/etc/modprobe.d/` directory
     - Run `modprobe -r squashfs 2>/dev/null; rmmod squashfs 2>/dev/null` to remove `squashfs` from the kernel

    - IF - the `squashfs` kernel module is not available on the system, or pre-compiled into the kernel, no remediation is necessary

    ```
    #!/usr/bin/env bash

    {
       unset a_output2; l_output3=\"\" l_dl=\"\" # unset arrays and clear variables
       l_mod_name=\"squashfs\" # set module name
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
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.1.1.6'
  tag cis_number:            '1.1.1.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01010106r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  impact 0.5
  describe kernel_module('squashfs') do
    it { should_not be_loaded }
    it { should be_disabled }
  end
end