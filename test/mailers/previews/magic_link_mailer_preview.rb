# frozen_string_literal: true

class MagicLinkMailerPreview < ActionMailer::Preview
  def login_link
    request = MagicLinkRequest.new(
      email: 'alumni@example.com',
      expires_at: 15.minutes.from_now,
      sent_at: Time.zone.now,
      metadata: { 'redirect_path' => '/welcome-back' }
    )

    MagicLinkMailer.login_link(request, raw_token: SecureRandom.hex(16))
  end
end
