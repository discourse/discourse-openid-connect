require 'omniauth-oauth2'

module ::OmniAuth
  module Strategies
    class OpenIDConnect < OmniAuth::Strategies::OAuth2
      option :scope, "openid"
      option :discovery, true
      option :cache, lambda { |key, &blk| blk.call } # Default no-op cache
      option :error_handler, lambda { |error, message| nil } # Default no-op handler
      option :authorize_options, [:p]

      option :client_options,
        site: 'https://op.com/',
        authorize_url: 'authorize',
        token_url: 'token',
        userinfo_endpoint: 'userinfo',
        auth_scheme: :basic_auth

      def discover!
        discovery_document = options.cache.call("openid_discovery_#{options[:client_options][:discovery_document]}") do
          client.request(:get, options[:client_options][:discovery_document], parse: :json).parsed
        end
        options[:client_options][:authorize_url] = discovery_document["authorization_endpoint"].to_s
        options[:client_options][:token_url] = discovery_document["token_endpoint"].to_s
        options[:client_options][:userinfo_endpoint] = discovery_document["userinfo_endpoint"].to_s
        options[:client_options][:site] = discovery_document["issuer"].to_s
      end

      def request_phase
        discover! if options[:discovery]
        super
      end

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end

          params[:scope] = options[:scope]
          session['omniauth.nonce'] = params[:nonce] = SecureRandom.hex(32)
        end
      end

      uid { id_token_info['sub'] }

      info do
        data_source = options.use_userinfo ? userinfo_response : id_token_info
        prune!(
          name: data_source['name'],
          email: data_source['email'],
          first_name: data_source['given_name'],
          last_name: data_source['family_name'],
          nickname: data_source['preferred_username'],
          picture: data_source['picture']
        )
      end

      extra do
        hash = {}
        hash[:raw_info] = options.use_userinfo ? userinfo_response : id_token_info
        prune! hash
      end

      def userinfo_response
        @raw_info ||= access_token.get(options[:client_options][:userinfo_endpoint]).parsed
        return fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected")) unless @raw_info['sub'] == id_token_info['sub']
        @raw_info
      end

      def id_token_info
        # Verify the claims in the JWT
        # The signature does not need to be verified because the
        # token was acquired via a direct server-server connection to the issuer
        @id_token_info ||= JWT.decode(
          access_token['id_token'], nil, false,
            :verify_iss => true,
            'iss' => options[:client_options][:site],
            :verify_aud => true,
            'aud' => options.client_id,
            :verify_sub => false,
            :verify_expiration => true,
            :verify_not_before => true,
            :verify_iat => true,
            :verify_jti => false
          ).first
      end

      def callback_phase
        if request.params["error"] && request.params["error_reason"] && response = options.error_handler.call(request.params["error"], request.params["error_reason"])
          return redirect(response)
        end
        discover! if options[:discovery]
        oauth2_callback_phase = super
        return oauth2_callback_phase if env['omniauth.error']

        if id_token_info["nonce"].empty? || id_token_info["nonce"] != session.delete("omniauth.nonce")
          return fail!(:csrf_detected, CallbackError.new(:csrf_detected, "CSRF detected"))
        end
        oauth2_callback_phase
      end

      private

      def callback_url
        # return "http://localhost:8080/auth/callback/"
        full_host + script_name + callback_path
      end

      def get_token_options
        { redirect_uri: callback_url,
          grant_type: 'authorization_code',
          code: request.params["code"],
          client_id: options[:client_id],
          client_secret: options[:client_secret]
        }.merge(token_params.to_hash(symbolize_keys: true))
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      protected

      def build_access_token
        return super if options.use_userinfo
        response = client.request(:get, options[:client_options][:token_url], params: get_token_options)
        ::OAuth2::AccessToken.from_hash(client, response.parsed)
      end

    end
  end
end

OmniAuth.config.add_camelization 'openid_connect', 'OpenIDConnect'
