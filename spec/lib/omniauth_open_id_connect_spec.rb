# frozen_string_literal: true

require_relative '../../lib/omniauth_open_id_connect'

require 'webmock/rspec'
WebMock.disable_net_connect!

describe OmniAuth::Strategies::OpenIDConnect do
  # let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) do
    lambda do |*args|
      [200, {}, ['Hello.']]
    end
  end

  before do
    stub_request(:get, "https://id.example.com/.well-known/openid-configuration").
      to_return(status: 200, body: {
          "issuer": "https://id.example.com/",
          "authorization_endpoint": "https://id.example.com/authorize",
          "token_endpoint": "https://id.example.com/token",
          "userinfo_endpoint": "https://id.example.com/userinfo",
        }.to_json)
  end

  subject do
    OmniAuth::Strategies::OpenIDConnect.new(app, 'appid', 'secret',
      client_options: {
        discovery_document: "https://id.example.com/.well-known/openid-configuration"
      }

    ).tap do |strategy|
      # allow(strategy).to receive(:request) do
      #   request
      # end
    end
  end

  before { OmniAuth.config.test_mode = true }

  after { OmniAuth.config.test_mode = false }

  it "throws error for on invalid discovery document" do
    stub_request(:get, "https://id.example.com/.well-known/openid-configuration").
      to_return(status: 200, body: {
        "issuer": "https://id.example.com/",
        "token_endpoint": "https://id.example.com/token",
        "userinfo_endpoint": "https://id.example.com/userinfo",
      }.to_json)

    expect { subject.discover! }.to raise_error(::OmniAuth::OpenIDConnect::DiscoveryError)
  end

  it "disables userinfo if not included in discovery document" do
    stub_request(:get, "https://id.example.com/.well-known/openid-configuration").
      to_return(status: 200, body: {
        "issuer": "https://id.example.com/",
        "authorization_endpoint": "https://id.example.com/authorize",
        "token_endpoint": "https://id.example.com/token",
      }.to_json)

    subject.discover!
    expect(subject.options.use_userinfo).to eq(false)
  end

  context 'with valid discovery document' do
    before do
      stub_request(:get, "https://id.example.com/.well-known/openid-configuration").
        to_return(status: 200, body: {
          "issuer": "https://id.example.com/",
          "authorization_endpoint": "https://id.example.com/authorize",
          "token_endpoint": "https://id.example.com/token",
          "userinfo_endpoint": "https://id.example.com/userinfo",
        }.to_json)

      allow(subject).to receive(:request) do
        double("Request", params: { "p" => "someallowedvalue", "somethingelse" => "notallowed" })
      end

      subject.discover!
    end

    it "loads parameters correctly" do
      expect(subject.options.client_options.site).to eq("https://id.example.com/")
      expect(subject.options.client_options.authorize_url).to eq("https://id.example.com/authorize")
      expect(subject.options.client_options.token_url).to eq("https://id.example.com/token")
      expect(subject.options.client_options.userinfo_endpoint).to eq("https://id.example.com/userinfo")
    end

    describe "authorize parameters" do
      it "passes through allowed parameters" do
        expect(subject.authorize_params[:p]).to eq("someallowedvalue")
        expect(subject.authorize_params[:somethingelse]).to eq(nil)

        expect(subject.session["omniauth.param.p"]).to eq("someallowedvalue")
      end

      it "sets a nonce" do
        expect((nonce = subject.authorize_params[:nonce]).size).to eq(64)
        expect(subject.session['omniauth.nonce']).to eq(nonce)
      end
    end

    describe "token parameters" do
      it "passes through parameters from authorize phase" do
        expect(subject.authorize_params[:p]).to eq("someallowedvalue")
        allow(subject).to receive(:request) { double("Request", params: {}) }
        expect(subject.token_params[:p]).to eq("someallowedvalue")
      end
    end

    describe "callback_phase" do
      before do
        auth_params = subject.authorize_params

        allow(subject).to receive(:full_host).and_return("https://example.com")

        allow(subject).to receive(:request) do
          double("Request", params: { "state" => auth_params[:state], "code" => "supersecretcode" })
        end

        payload = {
          iss: "https://id.example.com/",
          sub: "someuserid",
          aud: "appid",
          iat: Time.now.to_i - 30,
          exp: Time.now.to_i + 120,
          nonce: auth_params[:nonce],
          name: "My Auth Token Name",
          email: "tokenemail@example.com"
        }
        @token = JWT.encode payload, nil, 'none'
      end

      context "with userinfo disabled" do
        before do
          stub_request(:post, "https://id.example.com/token").
            with(body: hash_including("code" => "supersecretcode", "p" => "someallowedvalue")).
            to_return(status: 200, body: {
            "id_token": @token,
          }.to_json, headers: { "Content-Type" => "application/json" })

          subject.options.use_userinfo = false
        end

        it "fetches auth token correctly, and uses it for user info" do
          expect(subject.callback_phase[0]).to eq(200)
          expect(subject.uid).to eq("someuserid")
          expect(subject.info[:name]).to eq("My Auth Token Name")
          expect(subject.info[:email]).to eq("tokenemail@example.com")
        end

        it "checks the nonce" do
          subject.session["omniauth.nonce"] = "overriddenNonce"
          expect(subject.callback_phase[0]).to eq(302)
        end

        it "checks the issuer" do
          subject.options.client_id = "overriddenclientid"
          expect(subject.callback_phase[0]).to eq(302)
        end
      end

      context "with userinfo enabled" do
        before do
          stub_request(:post, "https://id.example.com/token").
            with(body: hash_including("code" => "supersecretcode", "p" => "someallowedvalue")).
            to_return(status: 200, body: {
            "access_token": "AnAccessToken",
            "expires_in": 3600,
            "id_token": @token,
          }.to_json, headers: { "Content-Type" => "application/json" })

          stub_request(:get, "https://id.example.com/userinfo").
            with(headers: { 'Authorization' => 'Bearer AnAccessToken' }).
            to_return(status: 200, body: {
              sub: "someuserid",
              name: "My Userinfo Name",
              email: "userinfoemail@example.com",
            }.to_json, headers: { "Content-Type" => "application/json" })
        end

        it "fetches credentials and auth token correctly" do
          expect(subject.callback_phase[0]).to eq(200)
          expect(subject.uid).to eq("someuserid")
          expect(subject.info[:name]).to eq("My Userinfo Name")
          expect(subject.info[:email]).to eq("userinfoemail@example.com")
        end
      end
    end
  end

end
