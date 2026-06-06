# encoding: UTF-8
#
# ami_provenance — provenance of the running instance's AMI (issue #4, host_lifecycle
# axis). On an ephemeral/immutable instance, filesystem integrity is established at
# image-build time and guaranteed by launching only from an organization-controlled
# AMI, rather than by runtime AIDE scanning. This resource reads the AMI id from IMDS
# and ec2:DescribeImages so a control can positively assert that provenance.
#
# Requires ec2:DescribeImages on the instance role (sparc-iac#368). When the
# gem/creds/IAM/IMDS are absent, available? is false and the control falls back to its
# SAF attestation. See AwsEvidenceBase.

# Load the base via Ruby require so AwsEvidenceBase resolves regardless of InSpec's
# alphabetical library-load order (the bare reference NameErrors at exec; check/json
# do not catch it).
require "aws_evidence_base"

class AmiProvenance < AwsEvidenceBase
  name "ami_provenance"
  supports platform: "unix"
  desc "Provenance of the running instance's AMI (owner / name / creation date)."
  example <<~EXAMPLE
    p = ami_provenance
    p.owned_by?(input('approved_ami_owners')) if p.available?
  EXAMPLE

  def initialize(opts = {})
    @opts = opts || {}
    @available = false
    return unless require_sdk("aws-sdk-ec2")

    region = aws_region
    return if region.nil?

    @ami_id = imds("/latest/meta-data/ami-id")
    if @ami_id.to_s.empty?
      @error = "could not resolve ami-id from IMDS (not on EC2 / IMDS unreachable)"
      return
    end

    img = Aws::EC2::Client.new(region: region).describe_images(image_ids: [@ami_id]).images.first
    if img.nil?
      @error = "DescribeImages returned no image for #{@ami_id}"
      return
    end
    @owner_id      = img.owner_id
    @name          = img.name
    @creation_date = img.creation_date
    @available     = true
  rescue StandardError => e
    @error     = "AMI provenance lookup failed: #{e.class}: #{e.message}"
    @available = false
  end

  attr_reader :ami_id, :owner_id, :name, :creation_date

  # True when the AMI owner is in the approved-owner allowlist (an empty allowlist
  # approves nothing — fail-closed).
  def owned_by?(approved_owners)
    Array(approved_owners).map(&:to_s).include?(@owner_id.to_s)
  end

  def to_s
    "AMI provenance (#{@ami_id || 'unknown'})"
  end
end
