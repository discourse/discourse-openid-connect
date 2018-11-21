# frozen_string_literal: true

require_relative '../../lib/omniauth_open_id_connect'

require 'webmock/rspec'
WebMock.disable_net_connect!

describe OmniAuth::Strategies::OpenIDConnect do
  # let(:request) { double('Request', params: {}, cookies: {}, env: {}) }
  let(:app) do
    lambda do
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

  context 'with valid document' do
    before do
      stub_request(:get, "https://id.example.com/.well-known/openid-configuration").
        to_return(status: 200, body: {
          "issuer": "https://id.example.com/",
          "authorization_endpoint": "https://id.example.com/authorize",
          "token_endpoint": "https://id.example.com/token",
          "userinfo_endpoint": "https://id.example.com/userinfo",
        }.to_json)
    end

    it "discovers correctly" do
      subject.discover!
      expect(subject.options.client_options.site).to eq("https://id.example.com/")
      expect(subject.options.client_options.authorize_url).to eq("https://id.example.com/authorize")
      expect(subject.options.client_options.token_url).to eq("https://id.example.com/token")
      expect(subject.options.client_options.userinfo_endpoint).to eq("https://id.example.com/userinfo")
    end
  end

end
