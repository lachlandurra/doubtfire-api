# frozen_string_literal: true

require 'omniauth'
require 'omniauth/rails_csrf_protection'

OmniAuth.config.logger = Rails.logger if defined?(Rails)
OmniAuth.config.allowed_request_methods = %i[get post]
OmniAuth.config.silence_get_warning = true
OmniAuth.config.path_prefix = '/api/auth/oauth'

Rails.application.config.middleware.use OmniAuth::Builder do
  oauth_config = Doubtfire::Application.config.try(:oauth_providers)
  next if oauth_config.blank?

  oauth_config.each do |provider_key, provider_settings|
    case provider_key.to_sym
    when :google
      client_id = provider_settings[:client_id]
      client_secret = provider_settings[:client_secret]
      redirect_uri = provider_settings[:redirect_uri]

      next if client_id.blank? || client_secret.blank? || redirect_uri.blank?

      options = {
        scope: provider_settings[:scope] || 'openid,email,profile',
        access_type: provider_settings[:access_type] || 'offline',
        prompt: provider_settings[:prompt] || 'select_account',
        hd: provider_settings[:hosted_domain],
        name: provider_key.to_s,
        path_prefix: '/api/auth/oauth',
        callback_path: "/api/auth/oauth/#{provider_key}/callback",
        redirect_uri: redirect_uri,
        pkce: provider_settings.fetch(:pkce, true)
      }.compact

      provider :google_oauth2, client_id, client_secret, options
    when :github
      client_id = provider_settings[:client_id]
      client_secret = provider_settings[:client_secret]
      redirect_uri = provider_settings[:redirect_uri]

      next if client_id.blank? || client_secret.blank?

      options = {
        scope: provider_settings[:scope] || 'read:user,user:email',
        name: provider_key.to_s,
        path_prefix: '/api/auth/oauth',
        callback_path: "/api/auth/oauth/#{provider_key}/callback",
        provider_ignores_state: false
      }.compact

      if redirect_uri.present?
        options[:client_options] = (
          provider_settings[:client_options] || {}
        ).merge(redirect_uri: redirect_uri)
      end

      provider :github, client_id, client_secret, options
    else
      Rails.logger.warn("Unsupported OAuth provider configured: #{provider_key}") if defined?(Rails)
    end
  end
end
