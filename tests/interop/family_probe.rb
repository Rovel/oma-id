# frozen_string_literal: true

# Parent sends fake credentials through stdin, never argv or a persistent file.
require "json"
input = JSON.parse($stdin.read)
ENV["OMA_P0_EXISTING_SCHEMA"] = input.fetch("schema")
require_relative "issuer"
require "rack/test"
session = Rack::Test::Session.new(Rack::MockSession.new(Lab::Application))
session.header "Host", "issuer.oma.test"
session.post "/oauth/token", input.fetch("params")
body = JSON.parse(session.last_response.body)
puts JSON.generate(status: session.last_response.status, error: body["error"])
