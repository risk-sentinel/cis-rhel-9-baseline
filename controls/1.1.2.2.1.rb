# encoding: UTF-8

control 'C-1.1.2.2.1' do
  title 'Ensure /dev/shm is a separate partition'
  desc  "
    The `/dev/shm` directory is a world-writable directory that can function as shared memory that facilitates inter process communication (IPC).

    Making `/dev/shm` its own file system allows an administrator to set additional mount options such as the `noexec` option on the mount, making `/dev/shm` useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to a system `setuid` program and wait for it to be updated. Once the program was updated, the hard link would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.

    This can be accomplished by mounting `tmpfs` to `/dev/shm`.
  "
  desc  'rationale', "
    The `/dev/shm` directory is a world-writable directory that can function as shared memory that facilitates inter process communication (IPC).

    Making `/dev/shm` its own file system allows an administrator to set additional mount options such as the `noexec` option on the mount, making `/dev/shm` useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to a system `setuid` program and wait for it to be updated. Once the program was updated, the hard link would be broken and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.

    This can be accomplished by mounting `tmpfs` to `/dev/shm`.
  "
  desc  'check', "
    - IF - `/dev/shm` is to be used on the system, run the following command and verify the output shows that `/dev/shm` is mounted. Particular requirements pertaining to mount options are covered in ensuing sections.

    ```
    # findmnt -kn /dev/shm
    ```

    _Example output:_

    ```
    /dev/shm   tmpfs  tmpfs  rw,nosuid,nodev,noexec,relatime,seclabel
    ```
  "
  desc  'fix', "
    For specific configuration requirements of the `/dev/shm` mount for your environment, modify `/etc/fstab`.

    _Example:_

    ```
    tmpfs	/dev/shm	tmpfs     defaults,rw,nosuid,nodev,noexec,relatime,size=2G  0 0
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag ksi:                   ['KSI-CMT-RMV', 'KSI-IAM-JIT']
  tag nist_r4:               ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.1.2.2.1'
  tag cis_number:            '1.1.2.2.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020201r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  # host_lifecycle axis: strict when /dev/shm is a distinct mount; ephemeral renders
  # N/A when /dev/shm is folded into root. See PostureRouting#fs_na?.
  if fs_na?('/dev/shm')
    impact 0.0
    describe '/dev/shm separate-mount isolation N/A (host_lifecycle=ephemeral; folded into root)' do
      subject { mount('/dev/shm').mounted? }
      it { is_expected.to eq false }
    end
  else
    impact 0.5
    describe mount('/dev/shm') do
      it { should be_mounted }
    end
  end
end
