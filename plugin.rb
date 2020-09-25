# frozen_string_literal: true

# name: discourse-openid-connect
# about: Add support for openid-connect as a login provider
# version: 1.0
# authors: David Taylor
# url: https://github.com/discourse/discourse-openid-connect

require_relative "lib/openid_connect_faraday_formatter"
require_relative "lib/omniauth_open_id_connect"
require_relative "lib/openid_connect_authenticator"

auth_provider authenticator: OpenIDConnectAuthenticator.new()
