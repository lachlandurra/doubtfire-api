# frozen_string_literal: true

require 'uri'
require 'securerandom'

module Api
  class OauthController < ApplicationController
    include LogHelper

    class StartFlowError < StandardError
      attr_reader :status

      def initialize(message, status: :bad_request)
        super(message)
        @status = status
      end
    end

    skip_before_action :verify_authenticity_token, only: %i[callback failure]
    before_action :ensure_oauth_enabled!
    before_action :ensure_valid_provider!

    PURPOSE_LOGIN = 'login'
    PURPOSE_LINK = 'link'
    SUPPORTED_PURPOSES = [PURPOSE_LOGIN, PURPOSE_LINK].freeze

    def start
      purpose = resolve_purpose
      linking_user = resolve_link_user(purpose)
      redirect_path = sanitise_redirect_path(params[:redirect_path]) || fallback_redirect_path
      provider_key = params[:provider].to_s

      state = OauthState.create!(
        token: SecureRandom.uuid,
        purpose: purpose,
        provider: provider_key,
        user: linking_user,
        redirect_path: redirect_path
      )

      logger.info("[OAuth] start request provider=#{provider_key} purpose=#{purpose} user_id=#{linking_user&.id} redirect_path=#{redirect_path}")

      redirect_to start_redirect_url(provider_key, state), allow_other_host: false
    rescue StartFlowError => e
      logger.warn("[OAuth] start rejected provider=#{params[:provider]} status=#{e.status} error=#{e.message}")
      render json: { error: e.message }, status: e.status
    rescue StandardError => e
      logger.error("[OAuth] start failed provider=#{params[:provider]} error=#{e.class.name} message=#{e.message}")
      render json: { error: 'OAuth sign-in could not be initiated.' }, status: :internal_server_error
    end

    def callback
      provider_key = params[:provider].to_s
      state_token = params[:state].to_s
      auth_hash = request.env['omniauth.auth']

      state = OauthState.find_by(token: state_token, provider: provider_key)
      if state.nil?
        logger.warn("[OAuth] callback without matching state provider=#{provider_key} state=#{state_token}")
        return redirect_to failure_redirect_url(provider_key, 'invalid_state')
      end

      if state_expired?(state)
        logger.warn("[OAuth] state expired before callback provider=#{provider_key} state=#{state_token}")
        state.destroy
        return redirect_to failure_redirect_url(provider_key, 'state_expired')
      end

      unless auth_hash.present?
        logger.error("[OAuth] callback missing auth hash provider=#{provider_key} state=#{state_token}")
        state.destroy
        return redirect_to failure_redirect_url(provider_key, 'missing_auth_hash')
      end

      resolver = Oauth::IdentityResolver.new(provider: provider_key, auth_hash: auth_hash, state: state)
      resolution = resolver.resolve!

      logger.info("[OAuth] identity resolved provider=#{provider_key} user_id=#{resolution.user.id} status=#{resolution.status}")

      login_token_params = issue_login_token_params(state, resolution.user)
      next_location = callback_redirect_url(state, resolution, login_token_params)
      state.destroy!

      redirect_to next_location
    rescue Oauth::IdentityResolver::ResolutionError => e
      logger.warn("[OAuth] identity resolution failed provider=#{params[:provider]} state=#{params[:state]} code=#{e.code} message=#{e.message}")
      redirect_to failure_redirect_url(params[:provider], e.code)
    rescue StandardError => e
      logger.error("[OAuth] callback processing failed provider=#{params[:provider]} error=#{e.class.name} message=#{e.message}")
      redirect_to failure_redirect_url(params[:provider], 'unexpected_error')
    ensure
      OauthState.cleanup_expired!
    end

    def failure
      provider_key = params[:strategy] || params[:provider] || 'unknown'
      message = params[:message] || params[:error_description] || params[:error_reason] || 'OAuth authentication failed.'
      logger.warn("[OAuth] provider callback failed provider=#{provider_key} message=#{message}")

      redirect_to failure_redirect_url(provider_key, params[:error] || 'oauth_failure', message: message)
    end

    private

    def ensure_oauth_enabled!
      return if Doubtfire::Application.config.oauth_enabled

      render json: { error: 'OAuth authentication is not available.' }, status: :not_found
    end

    def ensure_valid_provider!
      provider_key = params[:provider].to_s
      return if provider_key.present? && oauth_provider_config(provider_key).present?

      logger.warn("[OAuth] invalid provider requested provider=#{provider_key}")
      render json: { error: 'Unknown OAuth provider.' }, status: :not_found
    end

    def resolve_purpose
      requested = params[:purpose].presence || PURPOSE_LOGIN
      return requested if SUPPORTED_PURPOSES.include?(requested)

      logger.warn("[OAuth] unsupported start purpose requested purpose=#{requested}")
      PURPOSE_LOGIN
    end

    def resolve_link_user(purpose)
      return nil unless purpose == PURPOSE_LINK

      username = request.headers['Username'] || request.headers['username'] || params[:username]
      auth_token = request.headers['Auth-Token'] || request.headers['auth-token'] || params[:auth_token] || params[:authToken]

      if username.blank? || auth_token.blank?
        raise StartFlowError.new('Linking requires authenticated user context.', status: :bad_request)
      end

      user = User.eager_load(:auth_tokens).find_by(username: username.downcase)
      token = user&.token_for_text?(auth_token, :general)

      if user.nil? || token.nil? || token.auth_token_expiry <= Time.zone.now
        raise StartFlowError.new('Invalid authentication token.', status: :unauthorized)
      end

      user
    end

    def sanitise_redirect_path(raw)
      return nil if raw.blank?

      uri = URI.parse(raw)
      if uri.host.present?
        return raw if allowed_redirect_uri?(uri)

        return nil
      else
        raw.starts_with?('/') ? raw : "/#{raw}"
      end
    rescue URI::InvalidURIError
      nil
    end

    def start_redirect_url(provider_key, state)
      query_string = { state: state.token }.to_query
      path = "/api/auth/oauth/#{provider_key}"
      query_string.present? ? "#{path}?#{query_string}" : path
    end

    def state_expired?(state)
      state.created_at < Time.zone.now - OauthState::EXPIRATION_WINDOW
    end

    def callback_redirect_url(state, resolution, login_token_params)
      redirect_path = resolution.redirect_path || state.redirect_path
      target = redirect_path.presence || default_callback_redirect_path

      append_resolution_details(target, resolution, login_token_params)
    end

    def default_callback_redirect_path
      configured = Doubtfire::Application.config.oauth_default_redirect_uri
      return ensure_sign_in_path(configured) if configured.present?

      institution_host = Doubtfire::Application.config.institution[:host]
      host = ensure_url_scheme(institution_host)
      return ensure_sign_in_path(host) if host.present?

      ensure_sign_in_path(request.base_url)
    end

    def append_resolution_details(path, resolution, login_token_params)
      uri = URI.parse(path)
      params = Rack::Utils.parse_nested_query(uri.query).merge(
        'oauth_status' => resolution.status,
        'oauth_user_id' => resolution.user.id,
        'oauth_linked_identity' => resolution.linked_identity,
        'oauth_new_user' => resolution.new_user
      ).merge(login_token_params)
      uri.query = params.compact.to_query
      uri.to_s
    rescue URI::InvalidURIError
      default_callback_redirect_path
    end

    def fallback_redirect_path
      sanitise_redirect_path(request.referer)
    end

    def allowed_redirect_hosts
      Array(Doubtfire::Application.config.oauth_allowed_redirect_hosts)
    end

    def allowed_redirect_uri?(uri)
      allowed = allowed_redirect_hosts
      return true if allowed.empty?

      host = uri.host
      return false if host.blank?

      host_with_port = uri.port ? "#{host}:#{uri.port}" : host
      allowed.include?(host_with_port) || allowed.include?(host)
    end

    def ensure_sign_in_path(url)
      return nil if url.blank?

      normalized = ensure_url_scheme(url)
      return nil if normalized.blank?

      uri = URI.parse(normalized)

      uri.path = '/sign_in' if uri.path.blank? || uri.path == '/'
      uri.fragment = nil
      uri.to_s
    rescue URI::InvalidURIError
      url
    end

    def ensure_url_scheme(raw)
      return nil if raw.blank?

      uri = URI.parse(raw)
      return raw if uri.scheme.present?

      "https://#{raw}"
    rescue URI::InvalidURIError
      nil
    end

    def failure_redirect_url(provider, code, message: nil)
      fallback = default_callback_redirect_path
      uri = URI.parse(fallback)
      params = Rack::Utils.parse_nested_query(uri.query).merge(
        'oauth_error' => code.to_s,
        'oauth_error_message' => message || 'OAuth sign-in failed'
      )
      uri.query = params.to_query
      uri.to_s
    rescue URI::InvalidURIError
      fallback
    end

    def oauth_provider_config(provider_key)
      Doubtfire::Application.config.oauth_providers[provider_key]
    end

    def login_flow?(state)
      state.purpose == PURPOSE_LOGIN
    end

    def issue_login_token_params(state, user)
      return {} unless login_flow?(state)

      token = user.generate_temporary_authentication_token!
      {
        'authToken' => token.authentication_token,
        'username' => user.username
      }
    rescue StandardError => e
      logger.error("[OAuth] failed to issue temporary token user_id=#{user.id} error=#{e.class.name} message=#{e.message}")
      {}
    end
  end
end
