require 'rails_helper'
require_relative '../../lib/managed_authenticator'
describe Auth::ManagedAuthenticator do

  let(:authenticator) {
    Class.new(described_class).new do
      def name
        "myauth"
      end
    end
  }

  let(:hash) {
    {
      provider: "myauth",
      uid: "1234",
      info: {
        name: "Best Display Name",
        email: "awesome@example.com",
        nickname: "IAmGroot"
      },
      credentials: {
        token: "supersecrettoken"
      },
      extra: {
        raw_info: {
          randominfo: "some info"
        }
      }
    }
  }

  context 'after_authenticate' do
    it 'can match account from an existing association' do
      user = Fabricate(:user)
      associated = UserAssociatedAccount.create!(user: user, provider_name: 'myauth', provider_uid: "1234")
      result = authenticator.after_authenticate(hash)

      expect(result.user.id).to eq(user.id)
      associated.reload
      expect(associated.info["name"]).to eq("Best Display Name")
      expect(associated.info["email"]).to eq("awesome@example.com")
      expect(associated.credentials["token"]).to eq("supersecrettoken")
      expect(associated.extra["raw_info"]["randominfo"]).to eq("some info")
    end

    describe 'match by email' do
      it 'works normally' do
        user = Fabricate(:user)
        result = authenticator.after_authenticate(hash.deep_merge(info: { email: user.email }))
        expect(result.user.id).to eq(user.id)
      end

      it 'works if there is already an association with the target account' do
        user = Fabricate(:user, email: "awesome@example.com")
        result = authenticator.after_authenticate(hash)
        expect(result.user.id).to eq(user.id)
      end
    end
  end

end
