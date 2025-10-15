# frozen_string_literal: true

namespace :magic_link do
  desc 'Send a test magic link email using configured SMTP settings'
  task :test_delivery, %i[email redirect_path] => :environment do |_, args|
    email = args[:email] || ENV['MAGIC_LINK_TEST_EMAIL']
    if email.blank?
      raise ArgumentError, 'email is required (use `rails magic_link:test_delivery[email@example.com]`)'
    end

    redirect_path = args[:redirect_path].presence
    config = Doubtfire::Application.config.magic_link_config

    result = MagicLinks::Issuer.call(
      email: email,
      request_ip: '127.0.0.1',
      user_agent: 'magic_link:test_delivery',
      redirect_path: redirect_path,
      purpose: MagicLinkRequest::PURPOSE_LOGIN,
      config: config
    )

    MagicLinkMailer.login_link(result.request, raw_token: result.raw_token).deliver_now

    puts format(
      '[MagicLink] Sent test login link to %s (request id %s, expires %s)',
      email,
      result.request.id,
      (result.request.expires_at&.iso8601 || result.request.expires_at&.to_s || 'unknown expiry')
    )
  rescue MagicLinks::Issuer::RateLimitedError => e
    warn format('[MagicLink] Rate limited: retry after %ds', e.retry_after.to_i)
    raise
  end
end
