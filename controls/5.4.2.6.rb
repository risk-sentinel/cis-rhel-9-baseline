# encoding: UTF-8

control 'C-5.4.2.6' do
  title 'Ensure root user umask is configured'
  desc  "
    The user file-creation mode mask (`umask`) is used to determine the file permission for newly created directories and files. In Linux, the default permissions for any newly created directory is 0777 (`rwxrwxrwx`), and for any newly created file it is 0666 (`rw-rw-rw-`). The `umask` modifies the default Linux permissions by restricting (masking) these permissions. The `umask` is not simply subtracted, but is processed bitwise. Bits set in the `umask` are cleared in the resulting file mode.

    `umask` can be set with either `Octal` or `Symbolic` values:
    - `Octal` (Numeric) Value - Represented by either three or four digits. ie `umask 0027` or `umask 027`.  If a four digit umask is used, the first digit is ignored. The remaining three digits effect the resulting permissions for user, group, and world/other respectively.
    - `Symbolic` Value - Represented by a comma separated list for User `u`, group `g`, and world/other `o`.  The permissions listed are not masked by `umask`. ie a `umask` set by `umask u=rwx,g=rx,o=` is the `Symbolic` equivalent of the `Octal` `umask 027`.  This `umask` would set a newly created directory with file mode `drwxr-x---` and a newly created file with file mode `rw-r-----`.

    root user Shell Configuration Files:
    - `/root/.bash_profile` - Is executed to configure the root users' shell before the initial command prompt. Is only read by login shells.
    - `/root/.bashrc` - Is executed for interactive shells. only read by a shell that's both interactive and non-login

    `umask` is set by order of precedence. If `umask` is set in multiple locations, this order of precedence will determine the system's default `umask`.
 
    Order of precedence:
    1. `/root/.bash_profile`
    2. `/root/.bashrc`
    3. The system default umask

    Setting a secure value for `umask` ensures that users make a conscious choice about their file permissions. A permissive `umask` value could result in directories or files with excessive permissions that can be read and/or written to by unauthorized users.
  "
  desc  'rationale', "
    The user file-creation mode mask (`umask`) is used to determine the file permission for newly created directories and files. In Linux, the default permissions for any newly created directory is 0777 (`rwxrwxrwx`), and for any newly created file it is 0666 (`rw-rw-rw-`). The `umask` modifies the default Linux permissions by restricting (masking) these permissions. The `umask` is not simply subtracted, but is processed bitwise. Bits set in the `umask` are cleared in the resulting file mode.

    `umask` can be set with either `Octal` or `Symbolic` values:
    - `Octal` (Numeric) Value - Represented by either three or four digits. ie `umask 0027` or `umask 027`.  If a four digit umask is used, the first digit is ignored. The remaining three digits effect the resulting permissions for user, group, and world/other respectively.
    - `Symbolic` Value - Represented by a comma separated list for User `u`, group `g`, and world/other `o`.  The permissions listed are not masked by `umask`. ie a `umask` set by `umask u=rwx,g=rx,o=` is the `Symbolic` equivalent of the `Octal` `umask 027`.  This `umask` would set a newly created directory with file mode `drwxr-x---` and a newly created file with file mode `rw-r-----`.

    root user Shell Configuration Files:
    - `/root/.bash_profile` - Is executed to configure the root users' shell before the initial command prompt. Is only read by login shells.
    - `/root/.bashrc` - Is executed for interactive shells. only read by a shell that's both interactive and non-login

    `umask` is set by order of precedence. If `umask` is set in multiple locations, this order of precedence will determine the system's default `umask`.
 
    Order of precedence:
    1. `/root/.bash_profile`
    2. `/root/.bashrc`
    3. The system default umask

    Setting a secure value for `umask` ensures that users make a conscious choice about their file permissions. A permissive `umask` value could result in directories or files with excessive permissions that can be read and/or written to by unauthorized users.
  "
  desc  'check', "
    Run the following to verify the root user `umask` is set to enforce a newly created directories' permissions to be `750 (drwxr-x---)`, and a newly created file's permissions be `640 (rw-r-----)`, or more restrictive:

    ```
    grep -Psi -- '^\\h*umask\\h+(([0-7][0-7][01][0-7]\\b|[0-7][0-7][0-7][0-6]\\b)|([0-7][01][0-7]\\b|[0-7][0-7][0-6]\\b)|(u=[rwx]{1,3},)?(((g=[rx]?[rx]?w[rx]?[rx]?\\b)(,o=[rwx]{1,3})?)|((g=[wrx]{1,3},)?o=[wrx]{1,3}\\b)))' /root/.bash_profile /root/.bashrc

    Nothing should be returned
    ```
  "
  desc  'fix', "
    Edit `/root/.bash_profile` and `/root/.bashrc` and remove, comment out, or update any line with `umask` to be `0027` or more restrictive.
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-3', 'AC-8 a']
  tag nist_r4:               ['AC-3']
  tag cci:                   ['CCI-000213', 'CCI-000051']
  tag cis_rid:               '5.4.2.6'
  tag cis_number:            '5.4.2.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-05040206r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rPh -- '^\h*umask\h+0?[0-7]*[2367]7\b' /root/.bash_profile /root/.bashrc /root/.profile 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end