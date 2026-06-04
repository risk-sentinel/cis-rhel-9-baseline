# encoding: UTF-8

control 'C-3.1.3' do
  title 'Ensure bluetooth services are not in use'
  desc  "
    Bluetooth is a short-range wireless technology standard that is used for exchanging data between devices over short distances. It employs UHF radio waves in the ISM bands, from 2.402 GHz to 2.48 GHz. It is mainly used as an alternative to wire connections.

    An attacker may be able to find a way to access or corrupt your data. One example of this type of activity is `bluesnarfing`, which refers to attackers using a Bluetooth connection to steal information off of your Bluetooth device. Also, viruses or other malicious code can take advantage of Bluetooth technology to infect other devices. If you are infected, your data may be corrupted, compromised, stolen, or lost.
  "
  desc  'rationale', "
    Bluetooth is a short-range wireless technology standard that is used for exchanging data between devices over short distances. It employs UHF radio waves in the ISM bands, from 2.402 GHz to 2.48 GHz. It is mainly used as an alternative to wire connections.

    An attacker may be able to find a way to access or corrupt your data. One example of this type of activity is `bluesnarfing`, which refers to attackers using a Bluetooth connection to steal information off of your Bluetooth device. Also, viruses or other malicious code can take advantage of Bluetooth technology to infect other devices. If you are infected, your data may be corrupted, compromised, stolen, or lost.
  "
  desc  'check', "
    Run the following command to verify the `bluez` package is not installed:

    ```
    # rpm -q bluez

    package bluez is not installed
    ```

    - OR - 

    - IF - the `bluez` package is required as a dependency:

    Run the following command to verify `bluetooth.service` is not enabled:

    ```
    # systemctl is-enabled bluetooth.service 2>/dev/null | grep 'enabled'

    Nothing should be returned
    ```

    Run the following command to verify `bluetooth.service` is not active:

    ```
    # systemctl is-active bluetooth.service 2>/dev/null | grep '^active'

    Nothing should be returned
    ```

    Note: If the package is required for a dependency
     - Ensure the dependent package is approved by local site policy
     - Ensure stopping and masking the service and/or socket meets local site policy
  "
  desc  'fix', "
    Run the following commands to stop `bluetooth.service`, and remove the `bluez` package:

    ```
    # systemctl stop bluetooth.service
    # dnf remove bluez
    ```

    - OR -

    - IF - the `bluez` package is required as a dependency:

    Run the following commands to stop and mask `bluetooth.service`:

    ```
    # systemctl stop bluetooth.service
    # systemctl mask bluetooth.service
    ```

    Note: A reboot may be required
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '3.1.3'
  tag cis_number:            '3.1.3'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-030103r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'

  impact 0.5
  describe service('bluetooth') do
    it { should_not be_running }
    it { should_not be_enabled }
  end
end