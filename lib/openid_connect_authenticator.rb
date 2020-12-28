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
    if supplied_verified_boolean.nil?
      true
    else
      # Many providers violate the spec, and send this as a string rather than a boolean
      supplied_verified_boolean == true || supplied_verified_boolean == 'true'
    end
  end

  def always_update_user_email?
    SiteSetting.openid_connect_overrides_email
  end

  def discovery_document
    document_url = SiteSetting.openid_connect_discovery_document.presence
    if !document_url
      oidc_log("No discovery document URL specified", error: true)
      return
    end

    from_cache = true
    result = Discourse.cache.fetch("openid-connect-discovery-#{document_url}", expires_in: 10.minutes) do
      from_cache = false
      oidc_log("Fetching discovery document from #{document_url}")
      connection = Faraday.new { |c| c.use Faraday::Response::RaiseError }
      JSON.parse(connection.get(document_url).body)
    rescue Faraday::Error, JSON::ParserError => e
      oidc_log("Fetching discovery document raised error #{e.class} #{e.message}", error: true)
      nil
    end

    oidc_log("Discovery document loaded from cache") if from_cache
    oidc_log("Discovery document is\n\n#{result.to_yaml}")

    result
  end

  def after_authenticate(auth_token, existing_account: nil)
    result = super
    handle_group_memberships(result.user, auth_token)) if result.user
    result
  end

  def after_create_account(user, auth)
    super
    handle_group_memberships(user, auth[:extra_data])
  end

  def handle_group_memberships(user, auth_token)
    association = UserAssociatedAccount.find_or_initialize_by(
      provider_name: auth_token[:provider],
      provider_uid: auth_token[:uid]
    )
    return unless association && association.info
    
    added = []
    removed = []
    
    group_membership_claim_map.each do |gmc|
      if value = association.info[gmc.claim]
        is_member = [true, "true", "t"].include?(value) ||
          value == gmc.group.name ||
          value.is_a(String) && value.split(',').include?(gmc.group.name)
        
        if is_member && gmc.group.users.exclude?(user)
          gmc.group.add(user)
          added.push(gmc.group.name)
        end
        
        if !is_member && gm.group.users.include?(user) && gmc.modifiers.include?(:strict)
          gmc.group.remove(user)
          removed.push(gmc.group.name)
        end
      end
    end
    
    if added.any?
      oidc_log("added #{user.username} to groups: #{added.join(', ')}")
    end
    
    if removed.any?
      oidc_log("removed #{user.username} from groups: #{removed.join(', ')}")
    end
  end
  
  def group_membership_claim_map
    setting_list = SiteSetting.openid_connect_group_membership_claims.split('|')
    
    claims = {}
    setting_list.each do |result, setting|
      parts = setting.split('~~')
      claims[parts.second] = [parts.first, parts.last.split(',')]
    end
    
    Group.where(name: claims.keys, automatic: false).map do |group|
      OpenStruct.new(
        claim: claims[group.name].first,
        modifiers: validate_group_modifiers(claims[group.name].last),
        group: group
      )
    end
  end
  
  def validate_group_modifiers(modifers)
    modifier_map = {
      s: "strict"
    }
    modifers.reduce do |result, modifier|
      if mod_name = modifier_map[modifier]
        result.push(mod_name.to_sym)
      end
      result
    end
  end

  def oidc_log(message, error: false)
    if error
      Rails.logger.error("OIDC Log: #{message}")
    elsif SiteSetting.openid_connect_verbose_logging
      Rails.logger.warn("OIDC Log: #{message}")
    end
  end

  def register_middleware(omniauth)

    omniauth.provider :openid_connect,
      name: :oidc,
      error_handler: lambda { |error, message|
        handlers = SiteSetting.openid_connect_error_redirects.split("\n")
        handlers.each do |row|
          parts = row.split("|")
          return parts[1] if message.include? parts[0]
        end
        nil
      },
      verbose_logger: lambda { |message| oidc_log(message) },
      setup: lambda { |env|
        opts = env['omniauth.strategy'].options

        token_params = {}
        token_params[:scope] = SiteSetting.openid_connect_token_scope if SiteSetting.openid_connect_token_scope.present?

        opts.deep_merge!(
          client_id: SiteSetting.openid_connect_client_id,
          client_secret: SiteSetting.openid_connect_client_secret,
          discovery_document: discovery_document,
          scope: SiteSetting.openid_connect_authorize_scope,
          token_params: token_params,
          passthrough_authorize_options: SiteSetting.openid_connect_authorize_parameters.split("|")
        )

        if SiteSetting.openid_connect_verbose_logging
          opts[:client_options][:connection_build] = lambda { |builder|
            builder.response :logger, Rails.logger, { bodies: true, formatter: OIDCFaradayFormatter }

            # Default stack:
            builder.request :url_encoded             # form-encode POST params
            builder.adapter Faraday.default_adapter  # make requests with Net::HTTP
          }
        end

      }
  end
end
