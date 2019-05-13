# frozen_string_literal: true

# name: discourse-openid-connect
# about: Add support for openid-connect as a login provider
# version: 1.0
# authors: David Taylor
# url: https://github.com/discourse/discourse-openid-connect

require_relative "lib/omniauth_open_id_connect"

class OpenIDConnectAuthenticator < Auth::ManagedAuthenticator

  def name
    'oidc'
  end

  def can_revoke?
    SiteSetting.openid_connect_allow_association_change
  end

  def can_connect_existing_user?
    SiteSetting.openid_connect_allow_association_change
  end

  def enabled?
    SiteSetting.openid_connect_enabled
  end

  def register_middleware(omniauth)

    omniauth.provider :openid_connect,
      name: :oidc,
      cache: lambda { |key, &blk| Rails.cache.fetch(key, expires_in: 10.minutes, &blk) },
      error_handler: lambda { |error, message|
        handlers = SiteSetting.openid_connect_error_redirects.split("\n")
        handlers.each do |row|
          parts = row.split("|")
          return parts[1] if message.include? parts[0]
        end
        nil
      },
      verbose_logger: lambda { |message|
        return unless SiteSetting.openid_connect_verbose_logging
        Rails.logger.warn("OIDC Log: #{message}")
      },
      setup: lambda { |env|
        opts = env['omniauth.strategy'].options
        opts.deep_merge!(
          client_id: SiteSetting.openid_connect_client_id,
          client_secret: SiteSetting.openid_connect_client_secret,
          client_options: {
            discovery_document: SiteSetting.openid_connect_discovery_document,
          },
          scope: SiteSetting.openid_connect_authorize_scope,
          token_params: {
            scope: SiteSetting.openid_connect_token_scope,
          }
        )
      }
  end
end

# TODO: remove this check once Discourse 2.2 is released
if Gem.loaded_specs['jwt'].version > Gem::Version.create('2.0')
  auth_provider authenticator: OpenIDConnectAuthenticator.new(),
                full_screen_login: true
else
  STDERR.puts "WARNING: discourse-openid-connect requires Discourse v2.2.0.beta7 or above. The plugin will not be loaded."
end
