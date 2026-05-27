require 'test_helper'

class OauthIdentityResolverTest < ActiveSupport::TestCase
  def auth_hash(uid:, email:, email_verified: true)
    {
      'uid' => uid,
      'info' => {
        'email' => email,
        'email_verified' => email_verified,
        'name' => 'Graduate User'
      },
      'credentials' => {},
      'extra' => {}
    }
  end

  def test_existing_oauth_identity_resolves_to_same_user
    user = FactoryBot.create(:user, email: 'graduate-linked@example.edu')
    identity = user.link_oauth_identity!(
      provider: 'google',
      uid: 'google-linked-uid',
      verified_email: user.email,
      raw_info: {}
    )

    result = Oauth::IdentityResolver.new(
      provider: 'google',
      auth_hash: auth_hash(uid: identity.uid, email: user.email)
    ).resolve!

    assert_equal user.id, result.user.id
    assert_equal identity.id, result.identity.id
    assert_equal 'existing_identity', result.status
    refute result.new_user
  end

  def test_verified_provider_email_links_existing_ontrack_user
    user = FactoryBot.create(:user, email: 'graduate-email-match@example.edu')

    assert_difference('OauthIdentity.count', 1) do
      result = Oauth::IdentityResolver.new(
        provider: 'google',
        auth_hash: auth_hash(uid: 'google-new-uid', email: user.email)
      ).resolve!

      assert_equal user.id, result.user.id
      assert_equal 'matched_existing_user', result.status
      assert result.linked_identity
      refute result.new_user
    end
  end

  def test_unverified_provider_email_is_not_used_for_auto_linking
    user = FactoryBot.create(:user, email: 'graduate-unverified@example.edu')

    assert_no_difference('OauthIdentity.count') do
      error = assert_raises(Oauth::IdentityResolver::ResolutionError) do
        Oauth::IdentityResolver.new(
          provider: 'google',
          auth_hash: auth_hash(uid: 'google-unverified-uid', email: user.email, email_verified: false)
        ).resolve!
      end

      assert_equal 'no_matching_account', error.code
    end
  end

  def test_unknown_oauth_identity_is_rejected_without_creating_user
    assert_no_difference('User.count') do
      assert_no_difference('OauthIdentity.count') do
        error = assert_raises(Oauth::IdentityResolver::ResolutionError) do
          Oauth::IdentityResolver.new(
            provider: 'github',
            auth_hash: auth_hash(uid: 'github-unknown-uid', email: 'unknown-graduate@example.net')
          ).resolve!
        end

        assert_equal 'no_matching_account', error.code
      end
    end
  end

  def test_linking_flow_attaches_identity_to_authenticated_user_not_email_match
    # user_a and user_b share the same email domain but are different accounts.
    # user_b is logged in and initiates a link. The provider returns an email that
    # matches user_a. The resolver must bind to user_b (from the state), not user_a.
    user_a = FactoryBot.create(:user, email: 'shared-domain-a@example.edu')
    user_b = FactoryBot.create(:user, email: 'shared-domain-b@example.edu')
    link_state = OauthState.create!(token: SecureRandom.hex(16), purpose: 'link', provider: 'google', user: user_b)

    assert_difference('OauthIdentity.count', 1) do
      result = Oauth::IdentityResolver.new(
        provider: 'google',
        auth_hash: auth_hash(uid: 'google-new-uid', email: user_a.email),
        state: link_state
      ).resolve!

      assert_equal user_b.id, result.user.id
      assert_equal 'linked_identity', result.status
      assert result.linked_identity
    end
  end
end
