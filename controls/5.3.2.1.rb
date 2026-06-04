# encoding: UTF-8

control 'C-5.3.2.1' do
  title 'Ensure active authselect profile includes pam modules'
  desc  "
    A custom profile can be created by copying and customizing one of the default profiles. The default profiles include: sssd, winbind, and nis.  These profile can be customized to follow site specific requirements.

    You can select a profile for the authselect utility for a specific host. The profile will be applied to every user logging into the host.

    A custom profile is required to customize many of the pam options. 

    Modifications made to a default profile may be overwritten during an update.

    When you deploy a profile, the profile is applied to every user logging into the given host
  "
  desc  'rationale', "
    A custom profile can be created by copying and customizing one of the default profiles. The default profiles include: sssd, winbind, and nis.  These profile can be customized to follow site specific requirements.

    You can select a profile for the authselect utility for a specific host. The profile will be applied to every user logging into the host.

    A custom profile is required to customize many of the pam options. 

    Modifications made to a default profile may be overwritten during an update.

    When you deploy a profile, the profile is applied to every user logging into the given host
  "
  desc  'check', "
    Run the following command to verify the active authselect profile includes lines for the `pwquality`, `pwhistory`, `faillock`, and `unix` modules:

    ```
    # grep -P -- '\\b(pam_pwquality\\.so|pam_pwhistory\\.so|pam_faillock\\.so|pam_unix\\.so)\\b' /etc/authselect/\"$(head -1 /etc/authselect/authselect.conf)\"/{system,password}-auth
    ```

    _Example output:_

    ```
    /etc/authselect/custom/custom-profile/password-auth:auth   required   pam_faillock.so preauth silent {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/password-auth:auth   sufficient   pam_unix.so {if not \"without-nullok\":nullok}
    /etc/authselect/custom/custom-profile/password-auth:auth   required   pam_faillock.so authfail {include if \"with-faillock\"}

    /etc/authselect/custom/custom-profile/password-auth:account   required   pam_faillock.so {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/password-auth:account   required   pam_unix.so

    /etc/authselect/custom/custom-profile/password-auth:password   requisite   pam_pwquality.so local_users_only
    /etc/authselect/custom/custom-profile/password-auth:password  required   pam_pwhistory.so use_authtok
    /etc/authselect/custom/custom-profile/password-auth:password  sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok} use_authtok

    /etc/authselect/custom/custom-profile/password-auth:session   required   pam_unix.so


    /etc/authselect/custom/custom-profile/system-auth:auth   required   pam_faillock.so preauth silent {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/system-auth:auth   sufficient   pam_unix.so {if not \"without-nullok\":nullok}
    /etc/authselect/custom/custom-profile/system-auth:auth   required   pam_faillock.so authfail {include if \"with-faillock\"}

    /etc/authselect/custom/custom-profile/system-auth:account   required   pam_faillock.so {include if \"with-faillock\"}
    /etc/authselect/custom/custom-profile/system-auth:account     required   pam_unix.so

    /etc/authselect/custom/custom-profile/system-auth:password   requisite   pam_pwquality.so local_users_only
    /etc/authselect/custom/custom-profile/system-auth:password   required    pam_pwhistory.so use_authtok
    /etc/authselect/custom/custom-profile/system-auth:password   sufficient   pam_unix.so sha512 shadow {if not \"without-nullok\":nullok}

    /etc/authselect/custom/custom-profile/system-auth:session   required   pam_unix.so
    ```

    Notes:
    - The lines may or may not include feature options defined by text surrounded by curly brackets (`{}`) e.g. `{include if \"with-faillock\"}`
    - File path may be different due to the active profile in use
  "
  desc  'fix', "
    Perform the following to create a custom authselect profile, with the modules covered in this Benchmark correctly included in the custom profile template files
 
    Run the following command to create a custom authselect profile:

    ```
    # authselect create-profile ```

    _Example:_

    ```
    # authselect create-profile custom-profile -b sssd
    ```

    Run the following command to select a custom authselect profile:

    ```
    # authselect select custom/ {with- } {--force}
    ```

    _Example:_

    ```
    # authselect select custom/custom-profile --backup=PAM_CONFIG_BACKUP --force
    ```

    Notes: 
    - The PAM and authselect packages must be versions `pam-1.3.1-25` and `authselect-1.2.6-1` or newer
    - The example is based on a custom profile built (copied) from the the `SSSD` default authselect profile.
    - The example does not include the `symlink` option for the `PAM` or `Metadata` files.  This is due to the fact that by linking the `PAM` files future updates to `authselect` may overwrite local site customizations to the custom profile
    - The `--backup=PAM_CONFIG_BACKUP` option will create a backup of the current config. The backup will be stored at `/var/lib/authselect/backups/PAM_CONFIG_BACKUP`
    - The `--force` option will force the overwrite of the existing files and automatically backup system files before writing any change unless the `--nobackup` option is set.
      - On a new system where authselect has not been configured. In this case, the `--force` option will force the selected authselect profile to be active and overwrite the existing files with files generated from the selected authselect profile's templates
      - On an existing system with a custom configuration. The `--force` option may be used, but ensure that you note the backup location included as your custom files will be overwritten. This will allow you to review the changes and add any necessary customizations to the template files for the authselect profile. After updating the templates, run the command `authselect apply-changes` to add these custom entries to the files in `/etc/pam.d/`

    - IF - you receive an error ending with a message similar to:

    ```
    [error] Refusing to activate profile unless those changes are removed or overwrite is requested.
    Some unexpected changes to the configuration were detected. Use 'select' command instead.
    ```
 
    This error is caused when the previous configuration was not created by authselect but by other tool or by manual changes and the `--force` option will be required to enable the authselect profile.
  "
  tag severity:              'medium'
  tag nist:                  ['RA-5 a', 'CM-6 a']
  tag cci:                   ['CCI-001054', 'CCI-000363']
  tag cis_rid:               '5.3.2.1'
  tag cis_number:            '5.3.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05030201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{authselect current 2>/dev/null}) do
    its('stdout') { should match(%r{Profile ID|custom/}) }
  end
end