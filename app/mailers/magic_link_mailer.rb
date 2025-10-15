# frozen_string_literal: true

require 'uri'
require 'rack/utils'
require 'cgi'

class MagicLinkMailer < ActionMailer::Base
  def login_link(magic_link_request, raw_token:)
    raise ArgumentError, 'magic_link_request must be present' if magic_link_request.nil?
    raise ArgumentError, 'raw_token must be present' if raw_token.blank?

    @magic_link_request = magic_link_request
    @token = raw_token

    config = Doubtfire::Application.config.magic_link_config
    institution = Doubtfire::Application.config.institution

    @product_name = institution[:product_name] || 'OnTrack'
    @expires_at = magic_link_request.expires_at
    @support_email = config[:support_email]
    @redirect_path = magic_link_request.metadata&.dig('redirect_path')
    @magic_link_url = build_magic_link_url(config: config, token: raw_token, redirect_path: @redirect_path)

    mail(
      to: magic_link_request.email,
      from: config[:from_email].presence,
      subject: config[:subject].presence || "Your #{@product_name} magic link"
    )
  end

  private

  # Compose the callback URL while preserving existing fragment/query state.
  def build_magic_link_url(config:, token:, redirect_path:)
    base = config[:callback_url].presence || default_callback_url
    uri = URI.parse(base)

    extra_params = { 'token' => token }
    extra_params['redirectPath'] = redirect_path if redirect_path.present?

    if uri.fragment.present?
      fragment_path, fragment_query = uri.fragment.split('?', 2)
      fragment_params = Rack::Utils.parse_nested_query(fragment_query)
      updated_fragment_query = fragment_params.merge(extra_params).to_query
      uri.fragment = [fragment_path, updated_fragment_query.presence].compact.join('?')
    else
      existing_params = Rack::Utils.parse_nested_query(uri.query)
      merged_query = existing_params.merge(extra_params)
      uri.query = merged_query.to_query
    end

    uri.to_s
  rescue URI::InvalidURIError
    append_query_to_string_url(base, extra_params)
  end

  # Fallback for raw strings that fail URI parsing (e.g. custom deep links).
  def append_query_to_string_url(base, params)
    unless base.include?('#')
      separator = base.include?('?') ? '&' : '?'
      return "#{base}#{separator}#{Rack::Utils.build_query(params)}"
    end

    before_fragment, fragment = base.split('#', 2)
    fragment_path, fragment_query = fragment.to_s.split('?', 2)
    fragment_params = Rack::Utils.parse_nested_query(fragment_query)
    updated_fragment_query = fragment_params.merge(params).to_query
    "#{before_fragment}##{[fragment_path, updated_fragment_query.presence].compact.join('?')}"
  end

  def default_callback_url
    host = Doubtfire::Application.config.institution[:host].to_s
    host = "http://#{host}" unless host.include?('://')
    "#{host}/#/auth/magic-link"
  end
end
