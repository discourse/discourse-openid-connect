# frozen_string_literal: true

require 'rails_helper'

describe "OIDC RP-Initiated Logout" do
  let(:document_url) { SiteSetting.openid_connect_discovery_document = "https://id.example.com/.well-known/openid-configuration" }
  let(:document) do
    {
      "issuer": "https://id.example.com/",
      "authorization_endpoint": "https://id.example.com/authorize",
      "token_endpoint": "https://id.example.com/token",
      "userinfo_endpoint": "https://id.example.com/userinfo",
      "end_session_endpoint": "https://id.example.com/endsession",
    }.to_json
  end
  let(:user) { Fabricate(:user) }

  before do
    SiteSetting.openid_connect_enabled = true
    SiteSetting.openid_connect_rp_initiated_logout = true
    stub_request(:get, document_url).to_return(body: document)
  end

  after do
    Discourse.cache.delete("openid-connect-discovery-#{document_url}")
  end

  it "does nothing for a user with no oidc record" do
    sign_in(user)
    delete "/session/#{user.username}", xhr: true
    expect(response.status).to eq(200)
    expect(response.parsed_body["redirect_url"]).to eq("/")
  end

  it "does nothing for a user with no token in their oidc record" do
    sign_in(user)
    UserAssociatedAccount.create!(provider_name: "oidc", user: user, provider_uid: "myuid")
    delete "/session/#{user.username}", xhr: true
    expect(response.status).to eq(200)
    expect(response.parsed_body["redirect_url"]).to eq("/")
  end

  context "with user and token" do
    before do
      sign_in(user)
      UserAssociatedAccount.create!(provider_name: "oidc", user: user, provider_uid: "myuid", credentials: { token: "myoidctoken" })
    end

    it "redirects the user to the logout endpoint" do
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("https://id.example.com/endsession?id_token_hint=myoidctoken")
    end

    it "does not redirect if plugin disabled" do
      SiteSetting.openid_connect_enabled = false
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

    it "does not redirect if rp initiated logout disabled" do
      SiteSetting.openid_connect_rp_initiated_logout = false
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

    it "does not redirect if the discovery document is missing the endpoint" do
      stub_request(:get, document_url).to_return(body: "{}")
      SiteSetting.openid_connect_rp_initiated_logout = false
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

    it "does not redirect if the discovery document has a network error" do
      stub_request(:get, document_url).to_timeout
      SiteSetting.openid_connect_rp_initiated_logout = false
      delete "/session/#{user.username}", xhr: true
      expect(response.status).to eq(200)
      expect(response.parsed_body["redirect_url"]).to eq("/")
    end

  end

end
