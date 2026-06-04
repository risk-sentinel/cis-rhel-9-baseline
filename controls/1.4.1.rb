# encoding: UTF-8

control 'C-1.4.1' do
  title 'Ensure bootloader password is set'
  desc  "
    Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters.

    Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time).
  "
  desc  'rationale', "
    Setting the boot loader password will require that anyone rebooting the system must enter a password before being able to set command line boot parameters.

    Requiring a boot password upon execution of the boot loader will prevent an unauthorized user from entering boot parameters or changing the boot partition. This prevents users from weakening security (e.g. turning off SELinux at boot time).
  "
  desc  'check', "
    Run the following script to verify the bootloader password has been set:

    ```
    #!/usr/bin/env bash

    {
       l_grub_password_file=\"$(find /boot -type f -name 'user.cfg' ! -empty)\"
       if [ -f \"$l_grub_password_file\" ]; then
          awk -F. '/^\\s*GRUB2_PASSWORD=\\S+/ {print $1\".\"$2\".\"$3}' \"$l_grub_password_file\"
       fi
    }
    ```

    Output should be similar to:

    ```
    GRUB2_PASSWORD=grub.pbkdf2.sha512
    ```
  "
  desc  'fix', "
    Create an encrypted password with `grub2-setpassword`:

    ```
    # grub2-setpassword

    Enter password: Confirm password: ```
  "
  tag severity:              'medium'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.4.1'
  tag cis_number:            '1.4.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-010401r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -P -- '^\h*(set\h+superusers|GRUB2_PASSWORD)' /boot/grub2/user.cfg /boot/grub2/grub.cfg 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end