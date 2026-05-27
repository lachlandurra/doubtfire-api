# frozen_string_literal: true

module Oauth
  class IdentityResolver
    Resolution = Struct.new(
      :user,
      :identity,
      :status,
      :new_user,
      :linked_identity,
      :redirect_path,
      keyword_init: true
    )

    class ResolutionError < StandardError
      attr_reader :code

      def initialize(message, code: 'resolution_error')
        super(message)
        @code = code
      end
    end

    def initialize(provider:, auth_hash:, state: nil)
      @provider = provider.to_s
      @auth_hash = auth_hash
      @state = state
    end

    def resolve!
      raise ResolutionError.new('OAuth response missing provider or uid.', code: 'invalid_auth') if provider.blank? || uid.blank?

      if existing_identity
        update_existing_identity!
        already_linked = linking_flow? && existing_identity.user_id == state.user_id
        return build_resolution(existing_identity.user, existing_identity, status: 'existing_identity', linked: already_linked, new_user: false)
      end

      if linking_flow?
        user = linked_user_from_state
        identity = link_identity!(user)
        return build_resolution(user, identity, status: 'linked_identity', linked: true, new_user: false)
      end

      if match_user = locate_user_by_email
        identity = link_identity!(match_user)
        return build_resolution(match_user, identity, status: 'matched_existing_user', linked: true, new_user: false)
      end

      raise ResolutionError.new(
        'No existing OnTrack account matches this OAuth identity.',
        code: 'no_matching_account'
      )
    end

    private

    attr_reader :provider, :auth_hash, :state

    def uid
      @uid ||= auth_hash['uid'] || auth_hash[:uid]
    end

    def info
      @info ||= begin
        raw = auth_hash['info'] || auth_hash[:info] || {}
        raw.is_a?(Hash) ? raw.with_indifferent_access : raw
      end
    end

    def credentials
      @credentials ||= begin
        raw = auth_hash['credentials'] || auth_hash[:credentials] || {}
        raw.is_a?(Hash) ? raw.with_indifferent_access : raw
      end
    end

    def extra_raw_info
      raw_info = extra_context['raw_info'] || {}
      raw_info.is_a?(Hash) ? raw_info.with_indifferent_access : raw_info
    end

    def verified_email
      return info['email'] if truthy?(info['email_verified'])

      primary_entry = primary_email_entry
      return primary_entry[:email] if primary_entry && truthy?(primary_entry[:verified])

      if provider == 'github' && info['email'].present?
        return info['email']
      end

      nil
    end

    def primary_email
      info['email'].presence || extra_raw_info['email'].presence || primary_email_entry&.dig(:email)
    end

    def existing_identity
      @existing_identity ||= OauthIdentity.find_by(provider: provider, uid: uid)
    end

    def linking_flow?
      state&.purpose == 'link' && state.user.present?
    end

    def linked_user_from_state
      user = state&.user
      raise ResolutionError.new('Unable to link identity without user.', code: 'missing_user') if user.nil?

      user
    end

    def locate_user_by_email
      email = verified_email
      return nil if email.blank?

      User.find_by(email: email.downcase)
    end

    def link_identity!(user)
      ensure_identity_is_available!
      user.link_oauth_identity!(
        provider: provider,
        uid: uid,
        verified_email: verified_email,
        raw_info: merged_raw_info,
        refresh_token: credentials['refresh_token']
      )
    end

    def merged_raw_info
      enriched = extra_raw_info.merge(info) { |_, old, new| old.presence || new }
      emails = Array(extra_all_emails)
      enriched['emails'] = emails if emails.present?
      enriched
    end

    def update_existing_identity!
      identity = existing_identity
      identity.update!(
        verified_email: verified_email.presence || identity.verified_email,
        raw_info: merged_raw_info,
        refresh_token_encrypted: credentials['refresh_token'].presence || identity.refresh_token_encrypted,
        last_used_at: Time.zone.now
      )
    end

    def ensure_identity_is_available!
      conflict = OauthIdentity.find_by(provider: provider, uid: uid)
      return unless conflict && !linking_same_user?(conflict)

      raise ResolutionError.new('OAuth identity already linked to another user.', code: 'identity_claimed')
    end

    def extra_context
      @extra_context ||= begin
        raw = auth_hash['extra'] || auth_hash[:extra] || {}
        raw.is_a?(Hash) ? raw.with_indifferent_access : {}
      end
    end

    def extra_all_emails
      emails = extra_context[:all_emails]
      return [] unless emails.respond_to?(:map)

      emails.map do |entry|
        entry.is_a?(Hash) ? entry.with_indifferent_access : nil
      end.compact
    end

    def primary_email_entry
      emails = extra_all_emails
      primary = emails.find { |entry| truthy?(entry[:primary]) }
      primary || emails.first
    end

    def linking_same_user?(identity)
      return false if state&.user.nil?

      identity.user_id == state.user_id
    end

    def build_resolution(user, identity, status:, linked:, new_user:, redirect_path: nil)
      Resolution.new(
        user: user,
        identity: identity,
        status: status,
        linked_identity: linked,
        new_user: new_user,
        redirect_path: redirect_path
      )
    end

    def truthy?(value)
      value == true || value.to_s.casecmp('true').zero?
    rescue
      false
    end
  end
end
