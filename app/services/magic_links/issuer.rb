# frozen_string_literal: true

require 'securerandom'

module MagicLinks
  #
  # Issues single-use magic link tokens and enforces configurable rate limits.
  #
  class Issuer
    Result = Struct.new(
      :request,
      :raw_token,
      :user,
      :cooldown_seconds,
      keyword_init: true
    )

    class Error < StandardError
      attr_reader :code, :retry_after

      def initialize(message, code: 'magic_link_error', retry_after: nil)
        super(message)
        @code = code
        @retry_after = retry_after
      end
    end

    class RateLimitedError < Error
      def initialize(message, retry_after:)
        super(message, code: 'rate_limited', retry_after: retry_after)
      end
    end

    def self.call(...)
      new(...).call
    end

    def initialize(email:, request_ip:, user_agent:, redirect_path:, purpose:, config:)
      @raw_email = email
      @request_ip = request_ip.presence
      @user_agent = truncate(user_agent)
      @redirect_path = redirect_path
      @purpose = purpose.presence || MagicLinkRequest::PURPOSE_LOGIN
      @config = config || {}
    end

    def call
      now = Time.zone.now
      window_seconds = resend_window_seconds

      MagicLinkRequest.transaction do
        enforce_rate_limit!(now, window_seconds)

        raw_token = SecureRandom.hex(32)
        request = MagicLinkRequest.create!(
          token_digest: MagicLinkRequest.digest_for(raw_token),
          email: email,
          user: user,
          purpose: @purpose,
          sent_at: now,
          expires_at: now + token_ttl_seconds,
          request_ip: @request_ip,
          user_agent: @user_agent,
          metadata: build_metadata
        )

        Result.new(
          request: request,
          raw_token: raw_token,
          user: user,
          cooldown_seconds: window_seconds
        )
      end
    end

    private

    def email
      @email ||= @raw_email.to_s.strip.downcase
    end

    def user
      @user ||= begin
        return nil if email.blank?

        User.find_by_personal_email(email) ||
          User.find_by('LOWER(email) = ?', email)
      end
    end

    def resend_window_seconds
      value = @config[:resend_window_seconds].to_i
      value.positive? ? value : 120
    end

    def token_ttl_seconds
      value = @config[:token_ttl_seconds].to_i
      value.positive? ? value : 15.minutes.to_i
    end

    def max_attempts
      value = @config[:max_attempts].to_i
      value.positive? ? value : 3
    end

    # Apply rate limits across email and IP within the resend window.
    def enforce_rate_limit!(now, window_seconds)
      return if email.blank?

      window_start = now - window_seconds
      scope = MagicLinkRequest.where('sent_at >= ?', window_start)

      check_scope_rate_limit!(
        scope.where(email: email),
        now,
        window_seconds,
        'email'
      )

      if @request_ip.present?
        check_scope_rate_limit!(
          scope.where(request_ip: @request_ip),
          now,
          window_seconds,
          'ip'
        )
      end
    end

    # Raise a rate limit error when the scoped attempts exceed our threshold.
    def check_scope_rate_limit!(relation, now, window_seconds, dimension)
      return unless relation.count >= max_attempts

      earliest = relation.order(sent_at: :asc).first
      retry_after = [(earliest.sent_at + window_seconds - now).ceil, 0].max
      raise RateLimitedError.new(
        "Magic link requests temporarily limited for #{dimension}.",
        retry_after: retry_after
      )
    end

    def build_metadata
      data = ( { 'purpose' => @purpose } )
      data['redirect_path'] = @redirect_path if @redirect_path.present?
      data
    end

    def truncate(value, max = 500)
      str = value.to_s
      return str if str.length <= max

      str[0, max]
    end
  end
end
