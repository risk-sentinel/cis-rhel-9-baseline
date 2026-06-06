# encoding: UTF-8

control 'scan-target-inventory' do
  impact 0.0
  title 'Scan target inventory (informational)'
  desc "
    Captures the EC2 instance identity and host facts of the scanned target so the HDF
    carries 'what was assessed' provenance for the assessor — instance-id, AMI, account,
    instance-type, region/AZ, architecture, private IP, launch time, IAM role, OS/kernel,
    and (when ec2:DescribeInstances is permitted) VPC / subnet / state / Name tag.

    Informational only: impact 0.0 renders this Not Applicable in the HDF rollup, so it
    never counts as a pass or fail — it is provenance metadata, not a compliance check.
  "
  tag scan_target:           true
  tag implementation_status: 'inherited'

  inv = aws_instance_identity

  describe 'scan target' do
    if inv.fields.empty?
      it('instance identity could not be resolved (target is not an EC2 instance / IMDS unreachable)') do
        expect(true).to eq true
      end
    else
      inv.fields.each do |label, value|
        it("#{label} = #{value}") { expect(true).to eq true }
      end
    end
  end
end
