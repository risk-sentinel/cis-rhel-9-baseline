# encoding: UTF-8

control 'C-4.3.4' do
  title 'Ensure nftables loopback traffic is configured'
  desc  "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network

    Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  desc  'rationale', "
    Configure the loopback interface to accept traffic. Configure all other interfaces to deny traffic to the loopback network

    Loopback traffic is generated between processes on machine and is typically critical to operation of the system. The loopback interface is the only place that loopback network traffic should be seen, all other interfaces should ignore traffic on this network as an anti-spoofing measure.
  "
  desc  'check', "
    Run the following script to verify that the loopback interface is configured:

    -  `iif lo accept`
    -  `iif != lo ip saddr 127.0.0.1/8 drop`
    -  `iif != lo ip6 saddr ::1/128 drop`

    ```
    #!/usr/bin/env bash

    {
       l_output=\"\" l_output2=\"\" l_hbfw=\"\"
       if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
          echo -e \"\\n - FirewallD is in use on the system\\n - Recommendation is NA\" && l_hbfw=\"fwd\"
       elif systemctl is-enabled nftables.service | grep -q 'enabled'; then
          l_hbfw=\"nft\"
       else
          echo -e \"\\n - Error - Neither FirewallD or NFTables is enabled\\n - Please follow recommendation: \\\"Ensure a single firewall configuration utility is in use\\\"\"
          l_output2=\"* FAIL * Please follow recommendation: Ensure a single firewall configuration utility is in use\"
       fi
       if [ \"$l_hbfw\" = \"nft\" ]; then
          if nft list ruleset | awk '/hook\\s+input\\s+/,/\\}\\s*(#.*)?$/' | grep -Pq -- '\\H+\\h+\"lo\"\\h+accept'; then
             l_output=\"$l_output\\n - Network traffic to the loopback address is correctly set to accept\"
          else
             l_output2=\"$l_output2\\n - Network traffic to the loopback address is not set to accept\"
          fi
          l_ipsaddr=\"$(nft list ruleset | awk '/filter_IN_public_deny|hook\\s+input\\s+/,/\\}\\s*(#.*)?$/' | grep -P -- 'ip\\h+saddr')\"
          if grep -Pq -- 'ip\\h+saddr\\h+127\\.0\\.0\\.0\\/8\\h+(counter\\h+packets\\h+\\d+\\h+bytes\\h+\\d+\\h+)?drop' <<< \"$l_ipsaddr\" || grep -Pq -- 'ip\\h+daddr\\h+\\!\\=\\h+127\\.0\\.0\\.1\\h+ip\\h+saddr\\h+127\\.0\\.0\\.1\\h+drop' <<< \"$l_ipsaddr\"; then
             l_output=\"$l_output\\n - IPv4 network traffic from loopback address correctly set to drop\"
          else
             l_output2=\"$l_output2\\n - IPv4 network traffic from loopback address not set to drop\"
          fi
          if grep -Pq -- '^\\h*0\\h*$' /sys/module/ipv6/parameters/disable; then
             l_ip6saddr=\"$(nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6 saddr')\"
             if grep -Pq 'ip6\\h+saddr\\h+::1\\h+(counter\\h+packets\\h+\\d+\\h+bytes\\h+\\d+\\h+)?drop' <<< \"$l_ip6saddr\" || grep -Pq -- 'ip6\\h+daddr\\h+\\!=\\h+::1\\h+ip6\\h+saddr\\h+::1\\h+drop' <<< \"$l_ip6saddr\"; then
                l_output=\"$l_output\\n - IPv6 network traffic from loopback address correctly set to drop\"
             else
                l_output2=\"$l_output2\\n - IPv6 network traffic from loopback address not set to drop\"
             fi
          fi
       fi
       if [ \"$l_hbfw\" = \"fwd\" ] || [ -z \"$l_output2\" ]; then
          echo -e \"\\n- Audit Result:\\n  * PASS *\\n$l_output\"
       else
          echo -e \"\\n- Audit Result:\\n  * FAIL *\\n$l_output2\\n\\n  - Correctly set:\\n$l_output\"
       fi
    }
    ```
  "
  desc  'fix', "
    Run the following script to implement the loopback rules:

    ```
    #!/usr/bin/env bash

    {    l_hbfw=\"\"
         if systemctl is-enabled firewalld.service 2>/dev/null | grep -q 'enabled'; then
             echo -e \"\\n - FirewallD is in use on the system\\n - Recommendation is NA \\n - Remediation Complete\" && l_hbfw=\"fwd\"
        elif systemctl is-enabled nftables.service | grep -q 'enabled'; then
             l_hbfw=\"nft\"
          fi
          if [ \"$l_hbfw\" = \"nft\" ]; then 
             l_ipsaddr=\"$(nft list ruleset | awk '/filter_IN_public_deny|hook\\s+input\\s+/,/\\}\\s*(#.*)?$/' | grep -P -- 'ip\\h+saddr')\"
             if ! nft list ruleset | awk '/hook\\s+input\\s+/,/\\}\\s*(#.*)?$/' | grep -Pq -- '\\H+\\h+\"lo\"\\h+accept'; then
                echo -e \"\\n - Enabling input to accept for loopback address\"
                nft add rule inet filter input iif lo accept
             else
                echo -e \"\\n -nftables input correctly configured to accept for loopback address\"  
             fi
             if ! grep -Pq -- 'ip\\h+saddr\\h+127\\.0\\.0\\.0\\/8\\h+(counter\\h+packets\\h+\\d+\\h+bytes\\h+\\d+\\h+)?drop' <<< \"$l_ipsaddr\" && ! grep -Pq -- 'ip\\h+daddr\\h+\\!\\=\\h+127\\.0\\.0\\.1\\h+ip\\h+saddr\\h+127\\.0\\.0\\.1\\h+drop' <<< \"$l_ipsaddr\"; then
                echo -e \"\\n - Setting IPv4 network traffic from loopback address to drop\"
                nft add rule inet filter input ip saddr 127.0.0.0/8 counter drop
             else
                echo -e \"\\n -nftables correctly configured IPv4 network traffic from loopback address to drop\"
             fi
             if grep -Pq -- '^\\h*0\\h*$' /sys/module/ipv6/parameters/disable; then
                l_ip6saddr=\"$(nft list ruleset | awk '/filter_IN_public_deny|hook input/,/}/' | grep 'ip6 saddr')\"
                if ! grep -Pq 'ip6\\h+saddr\\h+::1\\h+(counter\\h+packets\\h+\\d+\\h+bytes\\h+\\d+\\h+)?drop' <<< \"$l_ip6saddr\" && ! grep -Pq -- 'ip6\\h+daddr\\h+\\!=\\h+::1\\h+ip6\\h+saddr\\h+::1\\h+drop' <<< \"$l_ip6saddr\"; then
                   echo -e \"\\n - Setting IPv6 network traffic from loopback address to drop\"        
                   nft add rule inet filter input ip6 saddr ::1 counter drop
                else 
                   echo -e \"\\n - nftables IPv6 network traffic from loopback address to drop\"   
             fi
             fi
          fi
    }
    ```
  "
  tag severity:              'medium'
  tag nist:                  ['SC-7 a', 'SC-18 (4)']
  tag cci:                   ['CCI-001097', 'CCI-002460']
  tag cis_rid:               '4.3.4'
  tag cis_number:            '4.3.4'
  tag cis_benchmark:         'CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0'
  tag cis_rule_id:           'SV-040304r1_rule'
  tag cis_version:           '2.0.0'
  tag cis_level:             1
  tag cis_scored:            true
  tag implementation_status: 'implemented'
  tag exec_validated:        true

  applicable = !service('firewalld').running?
  impact 0.5
  impact 0.0 unless applicable
  describe command(%q{nft list ruleset 2>/dev/null | grep -E 'iif "lo" accept'}) do
    its('stdout') { should match(/\S/) }
  end
  only_if('N/A unless nftables (standalone) is the active firewall (see 4.1.2)') { applicable }
end