require 'test_helper'

class MagicLinkAuthTest < ActiveSupport::TestCase
  include Rack::Test::Methods
  include TestHelpers::JsonHelper

  def app
    Rails.application
  end

  setup do
    @magic_link_config = Doubtfire::Application.config.magic_link.dup
    Doubtfire::Application.config.magic_link.enabled = true
    Doubtfire::Application.config.magic_link.token_ttl_seconds = 15.minutes.to_i
    Doubtfire::Application.config.magic_link.resend_window_seconds = 120
    Doubtfire::Application.config.magic_link.max_attempts = 3
    Doubtfire::Application.config.magic_link.auto_provision = false
  end

  teardown do
    Doubtfire::Application.config.magic_link = @magic_link_config
  end

  def create_magic_link(email:, user: nil, token: 'raw-token-value', expires_at: 15.minutes.from_now, consumed_at: nil)
    MagicLinkRequest.create!(
      token_digest: MagicLinkRequest.digest_for(token),
      email: email,
      user: user,
      purpose: MagicLinkRequest::PURPOSE_LOGIN,
      sent_at: Time.zone.now,
      expires_at: expires_at,
      consumed_at: consumed_at,
      metadata: { 'redirect_path' => '/portfolio' }
    )
  end

  def test_consume_magic_link_for_existing_personal_email_issues_temporary_token
    token = 'existing-user-token'
    user = FactoryBot.create(
      :user,
      personal_email: 'graduate@example.com',
      personal_email_verified_at: Time.zone.now
    )
    request_record = create_magic_link(email: user.personal_email, user: user, token: token)

    post_json '/api/auth/magic-link/consume', { token: token }

    assert_includes [200, 201], last_response.status
    body = last_response_body
    assert_equal user.username, body['username']
    assert_equal 'consumed', body['magic_link_status']
    assert_equal false, body['new_user']
    assert_equal '/portfolio', body['redirect_path']
    assert user.token_for_text?(body['auth_token'], :magic_link)
    assert request_record.reload.consumed_at.present?
  end

  def test_consume_magic_link_for_unknown_email_does_not_create_user
    token = 'unknown-user-token'
    create_magic_link(email: 'unknown-graduate@example.com', token: token)

    assert_no_difference('User.count') do
      post_json '/api/auth/magic-link/consume', { token: token }
    end

    assert_equal 404, last_response.status
    assert_equal 'user_not_found', last_response_body['code']
  end

  def test_expired_magic_link_is_rejected
    token = 'expired-token'
    user = FactoryBot.create(:user, personal_email: 'expired-graduate@example.com')
    create_magic_link(email: user.personal_email, user: user, token: token, expires_at: 1.minute.ago)

    post_json '/api/auth/magic-link/consume', { token: token }

    assert_equal 410, last_response.status
    assert_equal 'expired', last_response_body['code']
  end

  def test_consumed_magic_link_cannot_be_reused
    token = 'already-consumed-token'
    user = FactoryBot.create(:user, personal_email: 'used-graduate@example.com')
    create_magic_link(email: user.personal_email, user: user, token: token, consumed_at: Time.zone.now)

    post_json '/api/auth/magic-link/consume', { token: token }

    assert_equal 409, last_response.status
    assert_equal 'already_used', last_response_body['code']
  end

  def test_magic_link_issuance_is_rate_limited_by_email
    Doubtfire::Application.config.magic_link.max_attempts = 1

    post_json '/api/auth/magic-link', { email: 'limited-graduate@example.com' }
    assert_equal 202, last_response.status

    post_json '/api/auth/magic-link', { email: 'limited-graduate@example.com' }

    assert_equal 429, last_response.status
    assert_equal 'rate_limited', last_response_body['code']
  end
end
