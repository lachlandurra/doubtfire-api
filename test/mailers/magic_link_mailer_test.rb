require 'test_helper'
require 'securerandom'

class MagicLinkMailerTest < ActionMailer::TestCase
  setup do
    @original_callback_url = Doubtfire::Application.config.magic_link.callback_url
  end

  teardown do
    Doubtfire::Application.config.magic_link.callback_url = @original_callback_url
  end

  test 'default callback places token inside fragment query' do
    raw_token = SecureRandom.hex(8)
    request = build_request(raw_token)

    Doubtfire::Application.config.magic_link.callback_url = nil

    mail = MagicLinkMailer.login_link(request, raw_token: raw_token)

    expected_fragment = "#/auth/magic-link?token=#{raw_token}"
    assert_includes mail.body.encoded, expected_fragment
  end

  test 'custom callback preserves fragment path and adds redirect path param' do
    raw_token = SecureRandom.hex(8)
    redirect_path = '/projects/123'
    request = build_request(raw_token, metadata: { 'redirect_path' => redirect_path })

    Doubtfire::Application.config.magic_link.callback_url = 'https://app.example.com/#/auth/magic-link'

    mail = MagicLinkMailer.login_link(request, raw_token: raw_token)

    body = mail.body.encoded
    assert_includes body, '#/auth/magic-link?'
    assert_includes body, 'redirectPath=%2Fprojects%2F123'
    assert_includes body, "token=#{raw_token}"
  end

  private

  def build_request(raw_token, metadata: {})
    MagicLinkRequest.create!(
      token_digest: MagicLinkRequest.digest_for(raw_token),
      email: 'user@example.com',
      purpose: MagicLinkRequest::PURPOSE_LOGIN,
      sent_at: Time.zone.now,
      expires_at: 30.minutes.from_now,
      metadata: metadata
    )
  end
end
