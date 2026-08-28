# encoding: UTF-8
#
# aws_instance_identity — scan-target provenance for the assessor.
# Captures "what was assessed" so the HDF carries the instance identity alongside the
# findings, rather than the assessor having to reconcile it from a separate record.
#
# Primary source is the EC2 instance-identity document from IMDS
# (/latest/dynamic/instance-identity/document) — account, instance-id, instance-type,
# AMI, region, AZ, architecture, private IP, launch time — all HOST-VISIBLE, no IAM and
# no aws-sdk gem required. When the gem + ec2:DescribeInstances grant are present it
# enriches with VPC / subnet / state / Name tag; otherwise it degrades to the IMDS set.

# Load the base via Ruby require so AwsEvidenceBase resolves regardless of InSpec's
# alphabetical library-load order.
require "aws_evidence_base"
require "json"

class AwsInstanceIdentity < AwsEvidenceBase
  name "aws_instance_identity"
  supports platform: "unix"
  desc "EC2 instance identity + host facts for scan-target provenance (informational)."
  example <<~EXAMPLE
    aws_instance_identity.fields.each { |k, v| ... }
  EXAMPLE

  def initialize(opts = {})
    @opts   = opts || {}
    @fields = {}

    doc    = imds("/latest/dynamic/instance-identity/document")
    parsed = doc.to_s.empty? ? {} : (JSON.parse(doc) rescue {})
    @resolved = !parsed.empty?

    {
      "account_id"        => parsed["accountId"],
      "instance_id"       => parsed["instanceId"],
      "instance_type"     => parsed["instanceType"],
      "ami_id"            => parsed["imageId"],
      "region"            => parsed["region"],
      "availability_zone" => parsed["availabilityZone"],
      "architecture"      => parsed["architecture"],
      "private_ip"        => parsed["privateIp"],
      "launch_time"       => parsed["pendingTime"],
    }.each { |k, v| @fields[k] = v.to_s unless v.to_s.empty? }

    @fields["iam_role"] = imds("/latest/meta-data/iam/security-credentials/").to_s.strip
    @fields["hostname"] = host_cmd("hostname -f 2>/dev/null || hostname")
    @fields["kernel"]   = host_cmd("uname -r")
    begin
      @fields["os"] = "#{inspec.os.name} #{inspec.os.release}".strip
    rescue StandardError
      nil
    end

    enrich(parsed["instanceId"], parsed["region"]) if @resolved
    @fields.reject! { |_, v| v.to_s.empty? }
  end

  def resolved?
    @resolved == true
  end

  # Ordered label => value pairs (empty values dropped).
  def fields
    @fields
  end

  def one_line
    @fields.map { |k, v| "#{k}=#{v}" }.join(" ")
  end

  def to_s
    "Scan target #{@fields['instance_id'] || '(non-EC2)'}"
  end

  private

  def host_cmd(cmd)
    inspec.command(cmd).stdout.to_s.strip
  rescue StandardError
    ""
  end

  # Optional VPC / subnet / state / Name-tag enrichment; needs the gem + ec2:DescribeInstances.
  def enrich(iid, region)
    return if iid.to_s.empty? || region.to_s.empty?
    return unless require_sdk("aws-sdk-ec2")

    inst = Aws::EC2::Client.new(region: region)
             .describe_instances(instance_ids: [iid]).reservations.first&.instances&.first
    return if inst.nil?

    @fields["vpc_id"]    = inst.vpc_id.to_s
    @fields["subnet_id"] = inst.subnet_id.to_s
    @fields["state"]     = inst.state&.name.to_s
    name = inst.tags.find { |t| t.key == "Name" }&.value
    @fields["name_tag"]  = name.to_s if name
  rescue StandardError => e
    @fields["enrichment"] = "unavailable (#{e.class})"
  end
end
