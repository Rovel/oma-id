# P0 lab organization (ADR-0004: one organization per deployment). Idempotent.
# The canonical issuer defaults to the localhost origin; OMA_ID_ISSUER sets the
# value used for LAN experiments (e.g. http://198.51.100.10:3000). Changing the
# issuer of an existing organization is deliberately refused here — ADR-0004
# keeps the issuer stable across display-name changes.
default_issuer = ENV.fetch("OMA_ID_ISSUER", "http://localhost:3000")

if Organization.exists?
  existing = Organization.first!
  puts "Organization already seeded: #{existing.name} (issuer #{existing.issuer})"
  if ENV.key?("OMA_ID_ISSUER") && ENV["OMA_ID_ISSUER"] != existing.issuer
    puts "Refusing to change the canonical issuer of a seeded organization " \
         "(#{existing.issuer} -> #{ENV['OMA_ID_ISSUER']}). Reset the database to change it."
  end
else
  Organization.create!(
    name: ENV.fetch("OMA_ID_ORG_NAME", "OMA-ID Lab"),
    issuer: default_issuer,
    support_email: ENV.fetch("OMA_ID_SUPPORT_EMAIL", "id-admin@example.org")
  )
  puts "Seeded lab organization with issuer #{default_issuer}"
end
