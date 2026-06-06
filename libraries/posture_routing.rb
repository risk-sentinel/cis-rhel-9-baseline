# encoding: UTF-8
#
# PostureRouting — maps a declared posture axis value (or 'auto') to a concrete
# branch a control routes its assertion on (issue #4).
#
# Included into every control via ::Inspec::Rule.include. The leading `::` is
# required under InSpec 7: a bare `Inspec::Rule.include` raises an
# uninitialized-constant NameError at exec (check/json pass, exec fails to load).
#
# Fail-closed contract: 'auto' only ever resolves toward the strict/host branch.
# Routing a control to a cloud / off-box / attested branch is always an explicit
# consumer declaration — auto-detection never relaxes the strict path on its own,
# so a misconfigured or under-declared scan over-reports rather than silently passes.

module PostureRouting
  # platform_class: 'auto' is safe to resolve from DMI — cloud_nitro is a *correct*
  # classification, not a relaxation (its branch must still positively prove the
  # absence of an interactive boot path; it is not a free skip).
  def resolve_platform_class(declared)
    d = declared.to_s
    return d unless d == "auto"
    host_posture.aws_nitro? ? "cloud_nitro" : "baremetal"
  end

  # The remaining axes refuse to leave the strict/host branch on 'auto': the host
  # cannot positively prove a cloud SG, an off-box log destination, or a federated
  # access boundary, so 'auto' demands the host path and only an explicit declaration
  # routes to the compensating-evidence branch.
  def resolve_firewall(declared)
    d = declared.to_s
    d == "auto" ? "host_nftables" : d
  end

  def resolve_log_pipeline(declared)
    d = declared.to_s
    d == "auto" ? "onbox" : d
  end

  def resolve_host_lifecycle(declared)
    d = declared.to_s
    d == "auto" ? "persistent" : d
  end

  def resolve_access_model(declared)
    d = declared.to_s
    d == "auto" ? "interactive" : d
  end
end

::Inspec::Rule.include(PostureRouting)
