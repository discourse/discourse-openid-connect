# frozen_string_literal: true
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

  def primary_email_verified?(auth)
    supplied_verified_boolean = auth['extra']['raw_info']['email_verified']
    # If the payload includes the email_verified boolean, use it. Otherwise assume true
    supplied_verified_boolean.nil? ? true : supplied_verified_boolean
  end

  def always_update_user_email?
    SiteSetting.openid_connect_overrides_email
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
          },
          passthrough_authorize_options: SiteSetting.openid_connect_authorize_parameters.split("|")
        )
      }
  end
end
