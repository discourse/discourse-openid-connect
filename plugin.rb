# name: discourse-openid-connect
# about: Add support for openid-connect as a login provider
# version: 1.0
# authors: David Taylor
# url: https://github.com/discourse/discourse-openid-connect

require_relative "lib/omniauth_open_id_connect"
require_relative 'app/models/user_associated_account'

class Auth::ManagedAuthenticator < Auth::Authenticator
  def match_by_email
    true
  end

  def after_authenticate(auth_token)
    # puts "after authenticate ", auth_token.to_json

    result = Auth::Result.new

    result.authenticator_name = "OpenID Connect"

    result.extra_data = {
      provider: auth_token[:provider],
      uid: auth_token[:uid],
      info: auth_token[:info],
      extra: auth_token[:extra],
      credentials: auth_token[:credentials]
    }

    data = auth_token[:info]
    result.email = email = data[:email]
    result.name = name = "#{data[:first_name]} #{data[:last_name]}"
    result.username = data[:nickname]

    association = UserAssociatedAccount.find_by(provider_name: auth_token[:provider], provider_uid: auth_token[:uid])

    if match_by_email && association.nil? && user = User.find_by_email(email)
      association = UserAssociatedAccount.create!(user: user, provider_name: auth_token[:provider], provider_uid: auth_token[:uid], info: auth_token[:info], credentials: auth_token[:credentials], extra: auth_token[:extra])
    end

    result.user = association&.user
    result.email_valid = true

    result
  end

  def after_create_account(user, auth)
    data = auth[:extra_data]
    association = UserAssociatedAccount.create!(
      user: user,
      provider_name: data[:provider],
      provider_uid: data[:uid],
      info: data[:info],
      credentials: data[:credentials],
      extra: data[:extra]
    )
  end
end

class OpenIDConnectAuthenticator < Auth::ManagedAuthenticator

  def name
    'oidc'
  end

  def enabled?
    true
  end

  def register_middleware(omniauth)
    omniauth.provider :openid_connect,
      name: :oidc,
      cache: lambda { |key, &blk| Rails.cache.fetch(key, expires_in: 10.minutes, &blk) },
      setup: lambda { |env|
        opts = env['omniauth.strategy'].options
        opts.deep_merge!(
          use_userinfo: SiteSetting.openid_connect_use_userinfo,
          client_id: SiteSetting.openid_connect_client_id,
          client_secret: SiteSetting.openid_connect_client_secret,
          client_options: {
            discovery_document: SiteSetting.openid_connect_issuer,
          },
          scope: SiteSetting.openid_connect_authorize_scope,
          token_params: {
            scope: SiteSetting.openid_connect_token_scope,
          }
        )
      }
  end
end

auth_provider title: 'with OpenID Connect',
              authenticator: OpenIDConnectAuthenticator.new(),
              full_screen_login: true
