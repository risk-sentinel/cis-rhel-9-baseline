# encoding: UTF-8

control 'C-3.1.1' do
  title 'Ensure IPv6 status is identified'
  desc  "
    Internet Protocol Version 6 (IPv6) is the most recent version of Internet Protocol (IP). It's designed to supply IP addressing and additional security to support the predicted growth of connected devices. IPv6 is based on 128-bit addressing and can support 340 undecillion, which is 340,282,366,920,938,463,463,374,607,431,768,211,456 unique addresses.

    Features of IPv6
    - Hierarchical addressing and routing infrastructure
    - Statefull and Stateless configuration
    - Support for quality of service (QoS)
    - An ideal protocol for neighboring node interaction

    IETF RFC 4038 recommends that applications are built with an assumption of dual stack. It is recommended that IPv6 be enabled and configured in accordance with Benchmark recommendations.

    - IF - dual stack and IPv6 are not used in your environment, IPv6 may be disabled to reduce the attack surface of the system, and recommendations pertaining to IPv6 can be skipped.

    Note: It is recommended that IPv6 be enabled and configured unless this is against local site policy
  "
  desc  'rationale', "
    Internet Protocol Version 6 (IPv6) is the most recent version of Internet Protocol (IP). It's designed to supply IP addressing and additional security to support the predicted growth of connected devices. IPv6 is based on 128-bit addressing and can support 340 undecillion, which is 340,282,366,920,938,463,463,374,607,431,768,211,456 unique addresses.

    Features of IPv6
    - Hierarchical addressing and routing infrastructure
    - Statefull and Stateless configuration
    - Support for quality of service (QoS)
    - An ideal protocol for neighboring node interaction

    IETF RFC 4038 recommends that applications are built with an assumption of dual stack. It is recommended that IPv6 be enabled and configured in accordance with Benchmark recommendations.

    - IF - dual stack and IPv6 are not used in your environment, IPv6 may be disabled to reduce the attack surface of the system, and recommendations pertaining to IPv6 can be skipped.

    Note: It is recommended that IPv6 be enabled and configured unless this is against local site policy
  "
  desc  'check', "
    Run the following script to identify if IPv6 is enabled on the system:

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\"
       ! grep -Pqs -- '^\\h*0\\b' /sys/module/ipv6/parameters/disable && l_output=\"- IPv6 is not enabled\"
       if sysctl net.ipv6.conf.all.disable_ipv6 | grep -Pqs -- \"^\\h*net\\.ipv6\\.conf\\.all\\.disable_ipv6\\h*=\\h*1\\b\" && \\
          sysctl net.ipv6.conf.default.disable_ipv6 | grep -Pqs -- \"^\\h*net\\.ipv6\\.conf\\.default\\.disable_ipv6\\h*=\\h*1\\b\"; then
          l_output=\"- IPv6 is not enabled\"
       fi
       [ -z \"$l_output\" ] && l_output=\"- IPv6 is enabled\"
       echo -e \"\\n$l_output\\n\"
    }
    ```
  "
  desc  'fix', "
    Enable or disable IPv6 in accordance with system requirements and local site policy
  "
  impact 0.5
  tag severity:              'medium'
  tag nist:                  ['CM-7 a', 'SI-4 (11)']
  tag cci:                   ['CCI-000381', 'CCI-002668']
  tag cis_rid:               '3.1.1'
  tag cis_number:            '3.1.1'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-030101r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'alternative'
  tag attestation_category:  'operational'

  impact 0.5
  describe 'IPv6 status identified (3.1.1)' do
    skip 'operational: IPv6 enablement is a documented network-architecture decision (this CIS item only requires the status be identified, not a fixed state); operator records the IPv6 posture.'
  end
end