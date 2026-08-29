# encoding: UTF-8

control 'C-1.3.1.2' do
  title 'Ensure SELinux is not disabled in bootloader configuration'
  desc  "
    Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.

    SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden.
  "
  desc  'rationale', "
    Configure SELINUX to be enabled at boot time and verify that it has not been overwritten by the grub boot parameters.

    SELinux must be enabled at boot time in your grub configuration to ensure that the controls it provides are not overridden.
  "
  desc  'check', "
    Run the following command to verify that neither the `selinux=0` or `enforcing=0` parameters have been set:

    ```
    # grubby --info=ALL | grep -Po '(selinux|enforcing)=0\\b'
    ```

    Nothing should be returned
  "
  desc  'fix', "
    Run the following command to remove the `selinux=0` and `enforcing=0` parameters:

    ```
    grubby --update-kernel ALL --remove-args \"selinux=0 enforcing=0\"
    ```

    Run the following command to remove the `selinux=0` and `enforcing=0` parameters if they were created by the deprecated `grub2-mkconfig` command:

    ```
    # grep -Prsq -- '\\h*([^#\\n\\r]+\\h+)?kernelopts=([^#\\n\\r]+\\h+)?(selinux|enforcing)=0\\b' /boot/grub2 /boot/efi && grub2-mkconfig -o \"$(grep -Prl -- '\\h*([^#\\n\\r]+\\h+)?kernelopts=([^#\\n\\r]+\\h+)?(selinux|enforcing)=0\\b' /boot/grub2 /boot/efi)\"
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag ksi:                   ['KSI-IAM-APM', 'KSI-IAM-ELP', 'KSI-IAM-JIT']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '1.3.1.2'
  tag cis_number:            '1.3.1.2'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01030102r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grubby --info=ALL 2>/dev/null | grep -oE 'selinux=0|enforcing=0'}) do
    its('stdout.strip') { should be_empty }
  end
end