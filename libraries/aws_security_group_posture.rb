# encoding: UTF-8
#
# aws_security_group_posture — live ingress posture of the instance's security groups
# (issue #4, network_firewall axis). When ingress is enforced by AWS SGs rather than a
# host firewall, this asserts the cloud equivalent of "default-deny + drop unnecessary
# ports": no ingress rule opens a port to the world (0.0.0.0/0 or ::/0), and enumerates
# whatever world-open ports exist as evidence of the exposure surface.
#
# Reads the instance's SG ids (ec2:DescribeInstances on the IMDS instance-id) then their
# ingress rules (ec2:DescribeSecurityGroups). Requires those two on the instance role
# Missing gem/creds/IAM/IMDS => available?=false => SAF fallback.

# Load the base via Ruby require so AwsEvidenceBase resolves regardless of InSpec's
# alphabetical library-load order (the bare reference NameErrors at exec).
require "aws_evidence_base"

class AwsSecurityGroupPosture < AwsEvidenceBase
  name "aws_security_group_posture"
  supports platform: "unix"
  desc "Ingress posture (default-deny + world-open ports) of the instance's security groups."
  example <<~EXAMPLE
    describe aws_security_group_posture do
      it { should be_default_deny }
    end
  EXAMPLE

  def initialize(opts = {})
    @opts      = opts || {}
    @available = false
    return unless require_sdk("aws-sdk-ec2")

    region = aws_region
    return if region.nil?

    iid = instance_id
    if iid.to_s.empty?
      @error = "could not resolve instance-id from IMDS (not on EC2 / IMDS unreachable)"
      return
    end

    ec2  = Aws::EC2::Client.new(region: region)
    inst = ec2.describe_instances(instance_ids: [iid]).reservations.first&.instances&.first
    if inst.nil?
      @error = "DescribeInstances returned no instance for #{iid}"
      return
    end
    @sg_ids = inst.security_groups.map(&:group_id)
    if @sg_ids.empty?
      @error = "instance #{iid} has no security groups"
      return
    end

    @world_open = []
    ec2.describe_security_groups(group_ids: @sg_ids).security_groups.each do |sg|
      sg.ip_permissions.each do |perm|
        world = perm.ip_ranges.any? { |r| r.cidr_ip == "0.0.0.0/0" } ||
                perm.ipv_6_ranges.any? { |r| r.cidr_ipv_6 == "::/0" }
        next unless world
        @world_open << port_label(perm)
      end
    end
    @available = true
  rescue StandardError => e
    @error     = "SG posture lookup failed: #{e.class}: #{e.message}"
    @available = false
  end

  attr_reader :sg_ids

  # World-open ingress port labels (e.g. "22/tcp", "all"); the exposure surface.
  def world_open_ports
    @world_open || []
  end

  # True when no security group opens any port to the world — the cloud equivalent of a
  # default-deny ingress policy.
  def default_deny?
    @available == true && (@world_open || []).empty?
  end

  def to_s
    "SG ingress posture (#{(@sg_ids || []).join(',')})"
  end

  private

  def port_label(perm)
    return "all" if perm.ip_protocol == "-1"
    proto = perm.ip_protocol
    from  = perm.from_port
    to    = perm.to_port
    from == to ? "#{from}/#{proto}" : "#{from}-#{to}/#{proto}"
  end
end
