# frozen_string_literal: true

require 'securerandom'

module MagicLinks
  #
  # Validates magic link tokens and exchanges them for authenticated sessions.
  #
  class Verifier
    Result = Struct.new(
      :request,
      :user,
      :auth_token,
      :new_user,
      :status,
      :redirect_path,
      keyword_init: true
    )

    class Error < StandardError
      attr_reader :code

      def initialize(message, code: 'magic_link_error')
        super(message)
        @code = code
      end
    end

    class NotFoundError < Error
      def initialize
        super('Magic link is invalid.', code: 'not_found')
      end
    end

    class ExpiredError < Error
      def initialize
        super('Magic link has expired.', code: 'expired')
      end
    end

    class AlreadyUsedError < Error
      def initialize
        super('Magic link has already been used.', code: 'already_used')
      end
    end

    class UserNotFoundError < Error
      def initialize
        super('No account is associated with that email address.', code: 'user_not_found')
      end
    end

    def self.call(...)
      new(...).call
    end

    def initialize(token:, request_ip:, user_agent:, config:)
      @raw_token = token
      @request_ip = request_ip.presence
      @user_agent = truncate(user_agent)
      @config = config || {}
    end

    def call
      raise Error.new('Magic link token is required.', code: 'missing_token') if raw_token.blank?

      MagicLinkRequest.transaction do
        request = MagicLinkRequest.lock.find_by(token_digest: token_digest)
        raise NotFoundError.new if request.nil?
        raise ExpiredError.new if request.expired?
        raise AlreadyUsedError.new if request.consumed_at?

        user, new_user = resolve_user(request)
        redirect_path = request.metadata&.dig('redirect_path')

        apply_user_email_updates(user, request.email)

        auth_token = user.generate_temporary_authentication_token!(token_type: :magic_link)

        metadata = (request.metadata || {}).dup
        metadata['consumed_ip'] = @request_ip if @request_ip.present?
        metadata['consumed_user_agent'] = @user_agent if @user_agent.present?

        request.consume!(
          user_id: user.id,
          metadata: metadata
        )

        Result.new(
          request: request,
          user: user,
          auth_token: auth_token,
          new_user: new_user,
          status: 'consumed',
          redirect_path: redirect_path
        )
      end
    end

    private

    attr_reader :raw_token

    def token_digest
      @token_digest ||= MagicLinkRequest.digest_for(raw_token)
    end

    def auto_provision?
      value = @config[:auto_provision]
      return true if value == true

      %w[true 1 yes y].include?(value.to_s.strip.downcase)
    end

    # Locate the matching user or provision a new account when permitted.
    def resolve_user(request)
      user = request.user ||
             User.find_by_personal_email(request.email) ||
             User.find_by('LOWER(email) = ?', request.email)

      if user.present?
        [user, false]
      elsif auto_provision?
        [provision_user(request.email), true]
      else
        raise UserNotFoundError.new
      end
    end

    # Create a minimal student record when auto provisioning is enabled.
    def provision_user(email)
      local_part, domain = email.split('@', 2)
      username_base = local_part.to_s.gsub(/[^a-z0-9]/i, '').downcase
      username_base = "user#{SecureRandom.hex(2)}" if username_base.blank?
      username = unique_username(username_base)

      names = local_part.to_s.tr('.-_', ' ').split
      first_name = names.first&.capitalize || 'OnTrack'
      last_name = names.second&.capitalize || 'User'

      user = User.new(
        first_name: first_name,
        last_name: last_name,
        email: email,
        personal_email: email,
        personal_email_verified_at: Time.zone.now,
        username: username,
        nickname: first_name,
        role_id: Role.student_id,
        login_id: username
      )
      user.password = SecureRandom.hex(16)
      user.save!
      user
    end

    def unique_username(base)
      candidate = base
      counter = 1
      while User.exists?(username: candidate)
        counter += 1
        candidate = "#{base}#{counter}"
      end
      candidate
    end

    # Keep the user's personal email state in sync with the consumed request.
    def apply_user_email_updates(user, email)
      updated = false

      if user.personal_email.blank?
        user.personal_email = email
        updated = true
      end

      if user.personal_email_verified_at.nil?
        user.personal_email_verified_at = Time.zone.now
        updated = true
      end

      user.save! if updated
    end

    def truncate(value, max = 500)
      str = value.to_s
      return str if str.length <= max

      str[0, max]
    end
  end
end
