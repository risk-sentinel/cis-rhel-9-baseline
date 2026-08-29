# encoding: UTF-8

control 'C-1.2.1.1' do
  title 'Ensure GPG keys are configured'
  desc  "
    The RPM Package Manager implements GPG key signing to verify package integrity during and after installation.

    It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system. To this end, verify that GPG keys are configured correctly for your system.
  "
  desc  'rationale', "
    The RPM Package Manager implements GPG key signing to verify package integrity during and after installation.

    It is important to ensure that updates are obtained from a valid source to protect against spoofing that could lead to the inadvertent installation of malware on the system. To this end, verify that GPG keys are configured correctly for your system.
  "
  desc  'check', "
    List all GPG key URLs


    Each repository should have a `gpgkey` with a URL pointing to the location of the GPG key, either local or remote.

    ```
    # grep -r gpgkey /etc/yum.repos.d/* /etc/dnf/dnf.conf
    ```

    List installed GPG keys

    Run the following command to list the currently installed keys. These are the active keys used for verification and installation of RPMs. The packages are fake, they are generated on the fly by `dnf` or `rpm` during the import of keys from the URL specified in the repository configuration.

    _Example:_

    ```
    # for RPM_PACKAGE in $(rpm -q gpg-pubkey); do
      echo \"RPM: ${RPM_PACKAGE}\"
      RPM_SUMMARY=$(rpm -q --queryformat \"%{SUMMARY}\" \"${RPM_PACKAGE}\")
      RPM_PACKAGER=$(rpm -q --queryformat \"%{PACKAGER}\" \"${RPM_PACKAGE}\")
      RPM_DATE=$(date +%Y-%m-%d -d \"1970-1-1+$((0x$(rpm -q --queryformat \"%{RELEASE}\" \"${RPM_PACKAGE}\") ))sec\")
      RPM_KEY_ID=$(rpm -q --queryformat \"%{VERSION}\" \"${RPM_PACKAGE}\")
      echo \"Packager: ${RPM_PACKAGER}
    Summary: ${RPM_SUMMARY}
    Creation date: ${RPM_DATE}
    Key ID: ${RPM_KEY_ID}
    \"
    done

    RPM: gpg-pubkey-9db62fb1-59920156
    Packager: Fedora 28 (28) Summary: gpg(Fedora 28 (28) )
    Creation date: 2017-08-14
    Key ID: 9db62fb1

    RPM: gpg-pubkey-09eab3f2-595fbba3
    Packager: RPM Fusion free repository for Fedora (28) Summary: gpg(RPM Fusion free repository for Fedora (28) )
    Creation date: 2017-07-07
    Key ID: 09eab3f2
    ```

    The format of the package (`gpg-pubkey-9db62fb1-59920156`) is important to understand for verification. Using the above example, it consists of three parts:
    1. The general prefix name for all imported GPG keys: `gpg-pubkey-`
    2. The version, which is the GPG key ID: `9db62fb1`
    3. The release is the date of the key in UNIX timestamp in hexadecimal: `59920156`

    With both the date and the GPG key ID, check the relevant repositories public key page to confirm that the keys are indeed correct.

    Query locally available GPG keys

    Repositories that store their respective GPG keys on disk should do so in `/etc/pki/rpm-gpg/`. These keys are available for immediate import either when `dnf` is asked to install a relevant package from the repository or when an administrator imports the key directly with the `rpm --import` command.

    To find where these keys come from run:

    ```
    # for PACKAGE in $(find /etc/pki/rpm-gpg/ -type f -exec rpm -qf {} \\; | sort -u); do rpm -q --queryformat \"%{NAME}-%{VERSION} %{PACKAGER} %{SUMMARY}\\\\n\" \"${PACKAGE}\"; done
    ```
  "
  desc  'fix', "
    Update your package manager GPG keys in accordance with site policy.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['SI-12', 'MP-6 a', 'SI-2 a']
  tag ksi:                   ['KSI-CMT-VTD', 'KSI-RPL-ABO']
  tag nist_r4:               ['MP-6 a', 'SI-12', 'SI-2 a']
  tag cci:                   ['CCI-001678', 'CCI-001028', 'CCI-001225']
  tag cis_rid:               '1.2.1.1'
  tag cis_number:            '1.2.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-01020101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{rpm -q gpg-pubkey 2>/dev/null}) do
    its('stdout') { should match(/gpg-pubkey-[0-9a-f]/) }
  end
end