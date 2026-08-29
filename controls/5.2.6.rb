# encoding: UTF-8

control 'C-5.2.6' do
  title 'Ensure sudo authentication timeout is configured correctly'
  desc  "
    `sudo` caches used credentials for a default of 5 minutes. This is for ease of use when there are multiple administrative tasks to perform. The timeout can be modified to suit local security policies.

    Setting a timeout value reduces the window of opportunity for unauthorized privileged access to another user.
  "
  desc  'rationale', "
    `sudo` caches used credentials for a default of 5 minutes. This is for ease of use when there are multiple administrative tasks to perform. The timeout can be modified to suit local security policies.

    Setting a timeout value reduces the window of opportunity for unauthorized privileged access to another user.
  "
  desc  'check', "
    Ensure that the caching timeout is no more than 15 minutes.

    _Example:_

    ```
    # grep -roP \"timestamp_timeout=\\K[0-9]*\" /etc/sudoers*
    ```

    If there is no `timestamp_timeout` configured in `/etc/sudoers*` then the default is 5 minutes. This default can be checked with:

    ```
    # sudo -V | grep \"Authentication timestamp timeout:\"
    ```

    Note: A value of `-1` means that the timeout is disabled. Depending on the configuration of the `timestamp_type`, this could mean for all terminals / processes of that user and not just that one single terminal session.
  "
  desc  'fix', "
    If the currently configured timeout is larger than 15 minutes, edit the file listed in the audit section with `visudo -f ` and modify the entry `timestamp_timeout=` to 15 minutes or less as per your site policy. The value is in minutes. This particular entry may appear on its own, or on the same line as `env_reset`. See the following two examples:

    ```
    Defaults    env_reset, timestamp_timeout=15
    ```

    ```
    Defaults    timestamp_timeout=15
    Defaults    env_reset
    ```
  "
  tag severity:              'medium'
  tag severity_source:       'unassessed'
  tag nist:                  ['AC-11 b', 'AC-2 c']
  tag cci:                   ['CCI-000056', 'CCI-002113']
  tag cis_rid:               '5.2.6'
  tag cis_number:            '5.2.6'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-050206r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe command(%q{grep -rPi -- '^\h*Defaults\h+([^#\n\r]+,)?\h*timestamp_timeout\h*=' /etc/sudoers /etc/sudoers.d/ 2>/dev/null}) do
    its('stdout') { should match(/\S/) }
  end
end