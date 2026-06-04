# encoding: UTF-8

control 'C-1.1.2.1.1' do
  title 'Ensure /tmp is a separate partition'
  desc  "
    The `/tmp` directory is a world-writable directory used for temporary storage by all users and some applications.

    - IF - an entry for `/tmp` exists in `/etc/fstab` it will take precedence over entries in systemd default unit file.

    Note: In an environment where the main system is diskless and connected to iSCSI, entries in `/etc/fstab` may not take precedence.

    `/tmp` can be configured to use `tmpfs`. 

    `tmpfs` puts everything into the kernel internal caches and grows and shrinks to accommodate the files it contains and is able to swap unneeded pages out to swap space. It has maximum size limits which can be adjusted on the fly via `mount -o remount`.

    Since `tmpfs` lives completely in the page cache and on swap, all `tmpfs` pages will be shown as \"Shmem\" in `/proc/meminfo` and \"Shared\" in `free`. Notice that these counters also include shared memory. The most reliable way to get the count is using `df` and `du`.

    `tmpfs` has three mount options for sizing:
     - `size`: The limit of allocated bytes for this `tmpfs` instance. The default is half of your physical RAM without swap. If you oversize your `tmpfs` instances the machine will deadlock since the OOM handler will not be able to free that memory.
     - `nr_blocks`: The same as size, but in blocks of PAGE_SIZE.
     - `nr_inodes`: The maximum number of inodes for this instance. The default is half of the number of your physical RAM pages, or (on a machine with highmem) the number of lowmem RAM pages, whichever is the lower.

    These parameters accept a suffix k, m or g and can be changed on remount. The size parameter also accepts a suffix % to limit this `tmpfs` instance to that percentage of your physical RAM. The default, when neither `size` nor `nr_blocks` is specified, is `size=50%`.

    Making `/tmp` its own file system allows an administrator to set additional mount options such as the `noexec` option on the mount, making `/tmp` useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to a system `setuid` program and wait for it to be updated. Once the program was updated, the hard link would be broken, and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.

    This can be accomplished by either mounting `tmpfs` to `/tmp`, or creating a separate partition for `/tmp`.
  "
  desc  'rationale', "
    The `/tmp` directory is a world-writable directory used for temporary storage by all users and some applications.

    - IF - an entry for `/tmp` exists in `/etc/fstab` it will take precedence over entries in systemd default unit file.

    Note: In an environment where the main system is diskless and connected to iSCSI, entries in `/etc/fstab` may not take precedence.

    `/tmp` can be configured to use `tmpfs`. 

    `tmpfs` puts everything into the kernel internal caches and grows and shrinks to accommodate the files it contains and is able to swap unneeded pages out to swap space. It has maximum size limits which can be adjusted on the fly via `mount -o remount`.

    Since `tmpfs` lives completely in the page cache and on swap, all `tmpfs` pages will be shown as \"Shmem\" in `/proc/meminfo` and \"Shared\" in `free`. Notice that these counters also include shared memory. The most reliable way to get the count is using `df` and `du`.

    `tmpfs` has three mount options for sizing:
     - `size`: The limit of allocated bytes for this `tmpfs` instance. The default is half of your physical RAM without swap. If you oversize your `tmpfs` instances the machine will deadlock since the OOM handler will not be able to free that memory.
     - `nr_blocks`: The same as size, but in blocks of PAGE_SIZE.
     - `nr_inodes`: The maximum number of inodes for this instance. The default is half of the number of your physical RAM pages, or (on a machine with highmem) the number of lowmem RAM pages, whichever is the lower.

    These parameters accept a suffix k, m or g and can be changed on remount. The size parameter also accepts a suffix % to limit this `tmpfs` instance to that percentage of your physical RAM. The default, when neither `size` nor `nr_blocks` is specified, is `size=50%`.

    Making `/tmp` its own file system allows an administrator to set additional mount options such as the `noexec` option on the mount, making `/tmp` useless for an attacker to install executable code. It would also prevent an attacker from establishing a hard link to a system `setuid` program and wait for it to be updated. Once the program was updated, the hard link would be broken, and the attacker would have his own copy of the program. If the program happened to have a security vulnerability, the attacker could continue to exploit the known flaw.

    This can be accomplished by either mounting `tmpfs` to `/tmp`, or creating a separate partition for `/tmp`.
  "
  desc  'check', "
    Run the following command and verify the output shows that `/tmp` is mounted. Particular requirements pertaining to mount options are covered in ensuing sections.

    ```
    # findmnt -kn /tmp
    ```

    _Example output:_

    ```
    /tmp   tmpfs  tmpfs  rw,nosuid,nodev,noexec
    ```

    Ensure that systemd will mount the `/tmp` partition at boot time.

    ```
    # systemctl is-enabled tmp.mount
    ```

    _Example output:_

    ```
    generated
    ```

    Verify output is not `masked` or `disabled`.

    Note: By default, systemd will output `generated` if there is an entry in `/etc/fstab` for `/tmp`. This just means systemd will use the entry in `/etc/fstab` instead of its default unit file configuration for `/tmp`.
  "
  desc  'fix', "
    First ensure that systemd is correctly configured to ensure that `/tmp` will be mounted at boot time.

    ```
    # systemctl unmask tmp.mount
    ```

    For specific configuration requirements of the `/tmp` mount for your environment, modify `/etc/fstab`.

    Example of using `tmpfs` with specific mount options:

    ```
    tmpfs	/tmp	tmpfs     defaults,rw,nosuid,nodev,noexec,relatime,size=2G  0 0
    ```

    Note: the `size=2G` is an example of setting a specific size for `tmpfs`.

    Example of using a volume or disk with specific mount options. The source location of the volume or disk will vary depending on your environment:

    ``` /tmp defaults,nodev,nosuid,noexec   0 0
    ```
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '1.1.2.1.1'
  tag cis_number:            '1.1.2.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-0101020101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe mount('/tmp') do
    it { should be_mounted }
  end
end