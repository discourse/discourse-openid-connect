# frozen_string_literal: true

require 'rails_helper'
require_relative '../../lib/omniauth_open_id_connect'

describe OpenIDConnectAuthenticator do
  let(:authenticator) { described_class.new }
  let(:user) { Fabricate(:user) }
  let(:hash) { OmniAuth::AuthHash.new(
    provider: "oidc",
    uid: "123456789",
    info: {
        name: "John Doe",
        email: user.email
    },
    extra: {
      raw_info: {
        email: user.email,
        name: "John Doe"
      }
    }
  )}

  context "when email_verified is not supplied" do
    # Some IDPs do not supply this information
    # In this case we trust that they have verified the address
    it 'matches the user' do
      result = authenticator.after_authenticate(hash)

      expect(result.user).to eq(user)
    end
  end

  context "when email_verified is true" do
    it 'matches the user' do
      hash[:extra][:raw_info][:email_verified] = true
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end
  end

  context "when email_verified is false" do
    it 'does not match the user' do
      hash[:extra][:raw_info][:email_verified] = false
      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(nil)
    end
  end

end
