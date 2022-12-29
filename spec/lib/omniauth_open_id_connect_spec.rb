# frozen_string_literal: true

require_relative "../../lib/omniauth_open_id_connect"
require "rails_helper"

describe OmniAuth::Strategies::OpenIDConnect do
  let(:app) do
    @app_called = false
    lambda do |*args|
      @app_called = true
      [200, {}, ["Hello."]]
    end
  end

  let(:discovery_document) do
    {
      "issuer" => "https://id.example.com/",
      "authorization_endpoint" => "https://id.example.com/authorize",
      "token_endpoint" => "https://id.example.com/token",
      "userinfo_endpoint" => "https://id.example.com/userinfo",
    }
  end

  subject do
    OmniAuth::Strategies::OpenIDConnect.new(
      app,
      "appid",
      "secret",
      discovery_document: discovery_document,
    )
  end

  before { OmniAuth.config.test_mode = true }

  after { OmniAuth.config.test_mode = false }

  it "throws error for missing discovery document" do
    strategy =
      OmniAuth::Strategies::OpenIDConnect.new(app, "appid", "secret", discovery_document: nil)
    expect { strategy.discover! }.to raise_error(::OmniAuth::OpenIDConnect::DiscoveryError)
  end

  it "throws error for invalid discovery document" do
    discovery_document.delete("authorization_endpoint")
    expect { subject.discover! }.to raise_error(::OmniAuth::OpenIDConnect::DiscoveryError)
  end

  it "disables userinfo if not included in discovery document" do
    discovery_document.delete("userinfo_endpoint")
    subject.discover!
    expect(subject.options.use_userinfo).to eq(false)
  end

  it "uses basic authentication when no endpoint auth methods are provided" do
    subject.discover!
    expect(subject.options.client_options.auth_scheme).to eq(:basic_auth)
  end

  it "uses basic authentication when both client_secret_basic and client_secret_post are provided" do
    discovery_document.merge!(
      { "token_endpoint_auth_methods_supported" => %w[client_secret_basic client_secret_post] },
    )
    subject.discover!
    expect(subject.options.client_options.auth_scheme).to eq(:basic_auth)
  end

  it "uses request_body authentication when client_secret_post is provided only" do
    discovery_document.merge!({ "token_endpoint_auth_methods_supported" => ["client_secret_post"] })
    subject.discover!
    expect(subject.options.client_options.auth_scheme).to eq(:request_body)
  end

  context "with valid discovery document loaded" do
    before do
      subject.stubs(:request).returns(mock("object"))
      subject
        .request
        .stubs(:params)
        .returns("p" => "someallowedvalue", "somethingelse" => "notallowed")
      subject.options.claims = '{"userinfo":{"email":null,"email_verified":null}'
      subject.discover!
    end

    it "loads parameters correctly" do
      expect(subject.options.client_options.site).to eq("https://id.example.com/")
      expect(subject.options.client_options.authorize_url).to eq("https://id.example.com/authorize")
      expect(subject.options.client_options.token_url).to eq("https://id.example.com/token")
      expect(subject.options.client_options.userinfo_endpoint).to eq(
        "https://id.example.com/userinfo",
      )
    end

    describe "authorize parameters" do
      it "passes through allowed parameters" do
        expect(subject.authorize_params[:p]).to eq("someallowedvalue")
        expect(subject.authorize_params[:somethingelse]).to eq(nil)

        expect(subject.session["omniauth.param.p"]).to eq("someallowedvalue")
      end

      it "sets a nonce" do
        expect((nonce = subject.authorize_params[:nonce]).size).to eq(64)
        expect(subject.session["omniauth.nonce"]).to eq(nonce)
      end

      it "passes claims through to authorize endpoint if present" do
        expect(subject.authorize_params[:claims]).to eq(
          '{"userinfo":{"email":null,"email_verified":null}',
        )
      end

      it "does not pass claims if empty string" do
        subject.options.claims = ""
        expect(subject.authorize_params[:claims]).to eq(nil)
      end
    end

    describe "token parameters" do
      it "passes through parameters from authorize phase" do
        expect(subject.authorize_params[:p]).to eq("someallowedvalue")
        subject.stubs(:request).returns(mock)
        subject.request.stubs(:params).returns({})
        expect(subject.token_params[:p]).to eq("someallowedvalue")
      end
    end

    describe "callback_phase" do
      before do
        auth_params = subject.authorize_params

        subject.stubs(:full_host).returns("https://example.com")

        subject.stubs(:request).returns(mock)
        subject
          .request
          .stubs(:params)
          .returns("state" => auth_params[:state], "code" => "supersecretcode")

        payload = {
          iss: "https://id.example.com/",
          sub: "someuserid",
          aud: "appid",
          iat: Time.now.to_i - 30,
          exp: Time.now.to_i + 120,
          nonce: auth_params[:nonce],
          name: "My Auth Token Name",
          email: "tokenemail@example.com",
        }
        @token = ::JWT.encode payload, nil, "none"
      end

      it "handles error redirects correctly" do
        subject.stubs(:request).returns(mock)
        subject
          .request
          .stubs(:params)
          .returns("error" => true, "error_description" => "User forgot password")
        subject.options.error_handler =
          lambda do |error, message|
            return "https://example.com/error_redirect" if message.include?("forgot password")
          end
        expect(subject.callback_phase[0]).to eq(302)
        expect(subject.callback_phase[1]["Location"]).to eq("https://example.com/error_redirect")
        expect(@app_called).to eq(false)
      end

      context "with userinfo disabled" do
        before do
          stub_request(:post, "https://id.example.com/token").with(
            body: hash_including("code" => "supersecretcode", "p" => "someallowedvalue"),
          ).to_return(
            status: 200,
            body: { id_token: @token }.to_json,
            headers: {
              "Content-Type" => "application/json",
            },
          )

          subject.options.use_userinfo = false
        end

        it "fetches auth token correctly, and uses it for user info" do
          expect(subject.callback_phase[0]).to eq(200)
          expect(subject.uid).to eq("someuserid")
          expect(subject.info[:name]).to eq("My Auth Token Name")
          expect(subject.info[:email]).to eq("tokenemail@example.com")
          expect(subject.extra[:id_token]).to eq(@token)
          expect(@app_called).to eq(true)
        end

        it "checks the nonce" do
          subject.session["omniauth.nonce"] = "overriddenNonce"
          expect(subject.callback_phase[0]).to eq(302)
          expect(@app_called).to eq(false)
        end

        it "checks the issuer" do
          subject.options.client_id = "overriddenclientid"
          expect(subject.callback_phase[0]).to eq(302)
          expect(@app_called).to eq(false)
        end
      end

      context "with userinfo enabled" do
        let(:userinfo_response) do
          { sub: "someuserid", name: "My Userinfo Name", email: "userinfoemail@example.com" }
        end

        before do
          stub_request(:post, "https://id.example.com/token").with(
            body: hash_including("code" => "supersecretcode", "p" => "someallowedvalue"),
          ).to_return(
            status: 200,
            body: { access_token: "AnAccessToken", expires_in: 3600, id_token: @token }.to_json,
            headers: {
              "Content-Type" => "application/json",
            },
          )

          stub_request(:get, "https://id.example.com/userinfo")
            .with(headers: { "Authorization" => "Bearer AnAccessToken" })
            .to_return do |request|
              {
                status: 200,
                body: userinfo_response.to_json,
                headers: {
                  "Content-Type" => "application/json",
                },
              }
            end
        end

        it "fetches credentials and auth token correctly" do
          expect(subject.callback_phase[0]).to eq(200)
          expect(subject.uid).to eq("someuserid")
          expect(subject.info[:name]).to eq("My Userinfo Name")
          expect(subject.info[:email]).to eq("userinfoemail@example.com")
          expect(@app_called).to eq(true)
        end

        it "handles mismatching `sub` correctly" do
          userinfo_response["sub"] = "someothersub"
          callback_response = subject.callback_phase
          expect(callback_response[0]).to eq(302)
          expect(callback_response[1]["Location"]).to eq(
            "/auth/failure?message=openid_connect_sub_mismatch&strategy=openidconnect",
          )
          expect(@app_called).to eq(false)
        end
      end
    end
  end
end
