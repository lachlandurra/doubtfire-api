require 'grape'
require 'json/jwt'
require 'onelogin/ruby-saml'
require 'entities/user_entity'
require 'uri'

#
# Provides the authentication API for Doubtfire.
# Users can sign in via email and password and receive an auth token
# that can be used with other API calls.
#
class AuthenticationApi < Grape::API
  helpers LogHelper
  helpers AuthenticationHelpers
  helpers do
    # Guard endpoint access when magic link feature is disabled.
    def ensure_magic_link_available!
      error!({ error: 'Magic link authentication is not configured.' }, 404) unless magic_link_enabled?
    end

    # Restrict redirect targets to known hosts or relative paths.
    def sanitise_redirect_path(raw)
      return nil if raw.blank?

      uri = URI.parse(raw)
      if uri.host.present?
        return raw if magic_link_allowed_host?(uri)

        return nil
      end

      raw.starts_with?('/') ? raw : "/#{raw}"
    rescue URI::InvalidURIError
      nil
    end

    # Ensure callback hosts match the configured allowlist.
    def magic_link_allowed_host?(uri)
      allowed = Doubtfire::Application.config.magic_link_allowed_callback_hosts
      return true if allowed.blank?

      host = uri.host
      return false if host.blank?

      host_with_port = uri.port ? "#{host}:#{uri.port}" : host
      allowed.include?(host_with_port) || allowed.include?(host)
    end

    # Cached magic link service configuration.
    def magic_link_service_config
      Doubtfire::Application.config.magic_link_config
    end
  end

  #
  # Sign in - only mounted if AAF auth is NOT used
  #
  if AuthenticationHelpers.db_auth? || AuthenticationHelpers.ldap_auth?
    desc 'Sign in'
    params do
      requires :username, type: String, desc: 'User username'
      optional :password, type: String, desc: 'User\'s password'
      optional :auth_token, type: String, desc: 'Temporary authentication token for passwordless flows'
      optional :remember, type: Boolean, desc: 'User has requested to remember login', default: false
    end
    post '/auth' do
      username = params[:username]
      auth_token_param = params[:auth_token].presence
      password = params[:password]
      remember = params[:remember]
      logger.info "Authenticate #{username} from #{request.ip}"

      # Normalise username for lookup
      username = username.downcase
      institution_email_domain = Doubtfire::Application.config.institution[:email_domain]
      user = User.find_by('LOWER(username) = ?', username)

      if auth_token_param.present?
        error!({ error: 'Username is required for token exchange.' }, 400) if username.blank?
        error!({ error: 'Account not found.' }, 404) if user.nil?

        token = user.token_for_text?(auth_token_param)
        error!({ error: 'Invalid token.' }, 404) if token.nil?

        token.destroy!
        session_token = user.generate_authentication_token!(remember)

        logger.info "Token login #{username} from #{request.ip}"

        present :user, user, with: Entities::UserEntity
        present :auth_token, session_token.authentication_token
      else
        password = password.to_s

        # Truncate the 's' from sXXX for Swinburne auth
        truncate_s_match = (username =~ /^[Ss]\d{6,10}([Xx]|\d)$/)
        username = username[1..] if !truncate_s_match.nil? && truncate_s_match.zero?

        if username.blank? || password.blank?
          error!({ error: 'The request must contain the user username and password.' }, 400)
        end

        # User lookup or creation
        user ||= User.find_or_create_by(username: username) do |new_user|
          new_user.first_name = 'First Name'
          new_user.last_name  = 'Surname'
          new_user.email      = "#{username}@#{institution_email_domain}"
          new_user.nickname   = 'Nickname'
          new_user.role_id    = Role.student.id
          new_user.login_id   = username
        end

        unless user.authenticate?(password)
          error!({ error: 'Invalid email or password.' }, 401)
        end

        if user.new_record?
          user.encrypted_password = BCrypt::Password.create('password')

          unless user.valid?
            error!(error: 'There was an error creating your account in Doubtfire. ' \
                          'Please get in contact with your unit convenor or the ' \
                          'Doubtfire administrators.')
          end
          user.save
        end

        logger.info "Login #{username} from #{request.ip}"

        present :user, user, with: Entities::UserEntity
        present :auth_token, user.generate_authentication_token!(remember).authentication_token
      end
    end
  end

  #
  # AAF JWT callback - only mounted if AAF SAML is used
  # This isn't really a JWT, we will treat it as if it's a SAML response
  #
  if AuthenticationHelpers.saml_auth?
    desc 'SAML2.0 auth'
    params do
      requires :SAMLResponse, type: String, desc: 'Data provided for further processing.'
    end
    post '/auth/jwt' do
      response = OneLogin::RubySaml::Response.new(params[:SAMLResponse], allowed_clock_drift: 1.second,
                                                                         settings: AuthenticationHelpers.saml_settings)

      # We validate the SAML Response and check if the user already exists in the system
      return error!({ error: 'Invalid SAML response.' }, 401) unless response.is_valid?

      attributes = response.attributes

      login_id = response.name_id || response.nameid
      email = login_id

      logger.info "Authenticate #{email} from #{request.ip}"

      # Lookup using login_id if it exists
      # Lookup using email otherwise and set login_id
      # Otherwise create new
      user = User.find_by(login_id: login_id) ||
             User.find_by_username(email[/(.*)@/, 1]) ||
             User.find_by(email: email) ||
             User.find_or_create_by(login_id: login_id) do |new_user|
               role_response = attributes.fetch(/role/) || attributes.fetch(/userRole/)
               role = role_response.include?('Staff') ? Role.tutor.id : Role.student.id
               first_name = (attributes.fetch(/givenname/) || attributes.fetch(/cn/)).capitalize
               last_name = attributes.fetch(/surname/).capitalize
               username = email.split('@').first
               # Some institutions may provide givenname and surname, others
               # may only provide common name which we will use as first name
               new_user.first_name = first_name
               new_user.last_name  = last_name
               new_user.email      = email
               new_user.username   = username
               new_user.nickname   = first_name
               new_user.role_id    = role
             end

      # Set login id + username if not yet specified
      user.login_id = login_id if user.login_id.nil?
      user.username = username if user.username.nil?

      # Try and save the user once authenticated if new
      if user.new_record?
        user.encrypted_password = BCrypt::Password.create(SecureRandom.hex(32))
        unless user.valid?
          error!(error: 'There was an error creating your account in Doubtfire. ' \
                        'Please get in contact with your unit convenor or the ' \
                        'Doubtfire administrators.')
        end
        user.save
      end

      # Generate a temporary auth_token for future requests
      onetime_token = user.generate_temporary_authentication_token!

      logger.info "Redirecting #{user.username} from #{request.ip}"

      # Must redirect to the front-end after sign in
      host = Doubtfire::Application.config.institution[:host]
      unless host.starts_with?('http')
        protocol = Rails.env.development? ? 'http' : 'https'
        host = "#{protocol}://#{host}"
      end
      redirect "#{host}/#/sign_in?authToken=#{onetime_token.authentication_token}&username=#{user.username}"
    end
  end

  #
  # AAF JWT callback - only mounted if AAF auth is used
  #
  if AuthenticationHelpers.aaf_auth?
    desc 'AAF Rapid Connect JWT callback'
    params do
      requires :assertion, type: String, desc: 'Data provided for further processing.'
    end
    post '/auth/jwt' do
      jws = params[:assertion]
      error!({ error: 'JWS was not found in request.' }, 500) unless jws

      # Decode JWS
      jwt = User.decode_jws(jws)
      error!({ error: 'Invalid JWS.' }, 500) unless jwt

      # User lookup via unique login id
      attrs = jwt['https://aaf.edu.au/attributes']
      login_id = jwt[:sub]
      email = attrs[:mail]

      logger.info "Authenticate #{email} from #{request.ip}"

      # Lookup using login_id if it exists
      # Lookup using email otherwise and set login_id
      # Otherwise create new
      user = User.find_by(login_id: login_id) ||
             User.find_by_username(email[/(.*)@/, 1]) ||
             User.find_by(email: email) ||
             User.find_or_create_by(login_id: login_id) do |new_user|
               role = Role.aaf_affiliation_to_role_id(attrs[:edupersonscopedaffiliation])
               first_name = (attrs[:givenname] || attrs[:cn]).capitalize
               last_name = attrs[:surname].capitalize
               username = email.split('@').first
               # Some institutions may provide givenname and surname, others
               # may only provide common name which we will use as first name
               new_user.first_name = first_name
               new_user.last_name  = last_name
               new_user.email      = email
               new_user.username   = username
               new_user.nickname   = first_name
               new_user.role_id    = role
             end

      # Set login id + username if not yet specified
      user.login_id = login_id if user.login_id.nil?
      user.username = username if user.username.nil?

      # Try to authenticate
      return error!({ error: 'Invalid JSON web token.' }, 401) unless user.authenticate?(jws)

      # Try and save the user once authenticated if new
      if user.new_record?
        user.encrypted_password = BCrypt::Password.create(SecureRandom.hex(32))
        unless user.valid?
          error!(error: 'There was an error creating your account in Doubtfire. ' \
                        'Please get in contact with your unit convenor or the ' \
                        'Doubtfire administrators.')
        end
        user.save
      end

      # Generate a temporary auth_token for future requests
      onetime_token = user.generate_temporary_authentication_token!

      logger.info "Redirecting #{user.username} from #{request.ip}"

      # Must redirect to the front-end after sign in
      host = Doubtfire::Application.config.institution[:host]
      unless host.starts_with?('http')
        protocol = Rails.env.development? ? 'http' : 'https'
        host = "#{protocol}://#{host}"
      end
      redirect "#{host}/#/sign_in?authToken=#{onetime_token.authentication_token}&username=#{user.username}"
    end
  end

  if AuthenticationHelpers.saml_auth? || AuthenticationHelpers.aaf_auth?
    #
    # Respond user details provided a temporary login token
    #
    desc 'Get user details from an authentication token'
    params do
      requires :username, type: String, desc: 'The user\'s username'
      requires :auth_token, type: String, desc: 'The user\'s temporary auth token'
    end
    post '/auth' do
      error!({ error: 'Invalid token.' }, 404) if params[:auth_token].nil?
      logger.info "Get user via auth_token from #{request.ip}"

      # Authenticate that the token is okay
      if authenticated?
        user = User.find_by_username(params[:username])
        token = user.token_for_text?(params[:auth_token]) unless user.nil?
        error!({ error: 'Invalid token.' }, 404) if token.nil?

        # Invalidate the token and regenrate a new one
        token.destroy!
        token = user.generate_authentication_token! true

        logger.info "Login #{params[:username]} from #{request.ip}"

        # Respond user details with new auth token
        present :user, user, with: Entities::UserEntity
        present :auth_token, token.authentication_token
      end
    end
  end

  #
  # Returns the current auth method
  #
  desc 'Authentication method configuration'
  get '/auth/method' do
    response = {
      method: Doubtfire::Application.config.auth_method
    }
    response[:redirect_to] =
      if aaf_auth?
        Doubtfire::Application.config.aaf[:redirect_url]
      elsif saml_auth?
        request = OneLogin::RubySaml::Authrequest.new
        request.create(AuthenticationHelpers.saml_settings)
      end
    if magic_link_enabled?
      config = magic_link_config
      auto_provision_enabled = !!config[:auto_provision]
      response[:magic_link_enabled] = true
      response[:magic_link] = {
        token_ttl_seconds: config[:token_ttl_seconds],
        resend_window_seconds: config[:resend_window_seconds],
        max_attempts: config[:max_attempts],
        callback_url: config[:callback_url],
        default_redirect_path: config[:default_redirect_path],
        support_email: config[:support_email],
        allowed_callback_hosts: Doubtfire::Application.config.magic_link_allowed_callback_hosts,
        auto_provision: auto_provision_enabled,
        requires_personal_email: !auto_provision_enabled
      }.delete_if { |_, value| value.nil? }
    end
    present response, with: Grape::Presenters::Presenter
  end

  #
  # Issues a single-use login link and schedules the notification email
  #
  desc 'Request an email magic link'
  params do
    requires :email, type: String, desc: 'Email address to send the magic link to'
    optional :redirect_path, type: String, desc: 'Optional SPA path to redirect to after login'
    optional :purpose, type: String, desc: 'Purpose for the magic link', default: MagicLinkRequest::PURPOSE_LOGIN
  end
  post '/auth/magic-link' do
    ensure_magic_link_available!

    email_param = params[:email].to_s
    redirect_path = sanitise_redirect_path(params[:redirect_path])
    purpose = params[:purpose].presence || MagicLinkRequest::PURPOSE_LOGIN

    issuer_result = MagicLinks::Issuer.call(
      email: email_param,
      request_ip: request.ip,
      user_agent: request.user_agent,
      redirect_path: redirect_path,
      purpose: purpose,
      config: magic_link_service_config
    )

    logger.info "[MagicLink] issued request_id=#{issuer_result.request.id} email=#{issuer_result.request.email} user_id=#{issuer_result.user&.id} ip=#{request.ip}"

    notification_payload = {
      request_id: issuer_result.request.id,
      email: issuer_result.request.email,
      user_id: issuer_result.user&.id,
      purpose: issuer_result.request.purpose
    }

    ActiveSupport::Notifications.instrument('magic_link.sent', notification_payload) do
      MagicLinkMailer.login_link(issuer_result.request, raw_token: issuer_result.raw_token).deliver_later
    end

    status 202
    present(
      {
        status: 'sent',
        magic_link_status: 'pending',
        expires_at: issuer_result.request.expires_at.iso8601,
        cooldown_seconds: issuer_result.cooldown_seconds
      },
      with: Grape::Presenters::Presenter
    )
  rescue MagicLinks::Issuer::RateLimitedError => e
    headers['Retry-After'] = e.retry_after.to_s if e.retry_after
    logger.warn "[MagicLink] rate_limited email=#{email_param.downcase} ip=#{request.ip} retry_after=#{e.retry_after}"
    error!({ error: 'Magic link requests are temporarily limited. Please try again later.', code: e.code, retry_after: e.retry_after }, 429)
  rescue MagicLinks::Issuer::Error => e
    logger.warn "[MagicLink] issuer_error code=#{e.code} email=#{email_param.downcase} message=#{e.message}"
    error!({ error: e.message, code: e.code }, 400)
  rescue ActiveRecord::RecordInvalid => e
    logger.error "[MagicLink] issuer_invalid email=#{email_param.downcase} errors=#{e.record.errors.full_messages.join(', ')}"
    error!({ error: 'Unable to create magic link request.', code: 'validation_error' }, 422)
  end

  #
  # Validates a magic link token and returns an auth token for the SPA
  #
  desc 'Consume an email magic link'
  params do
    requires :token, type: String, desc: 'Magic link token'
  end
  post '/auth/magic-link/consume' do
    ensure_magic_link_available!

    token_param = params[:token].to_s
    token_digest = token_param.present? ? MagicLinkRequest.digest_for(token_param) : nil

    verifier_result = MagicLinks::Verifier.call(
      token: token_param,
      request_ip: request.ip,
      user_agent: request.user_agent,
      config: magic_link_service_config
    )

    logger.info "[MagicLink] consumed request_id=#{verifier_result.request.id} user_id=#{verifier_result.user.id} ip=#{request.ip}"

    auth_token = verifier_result.auth_token
    response = {
      auth_token: auth_token.authentication_token,
      username: verifier_result.user.username,
      expires_at: auth_token.auth_token_expiry&.iso8601,
      magic_link_status: verifier_result.status,
      new_user: verifier_result.new_user
    }
    response[:redirect_path] = verifier_result.redirect_path if verifier_result.redirect_path.present?

    present response, with: Grape::Presenters::Presenter
  rescue MagicLinks::Verifier::ExpiredError => e
    logger.warn "[MagicLink] expired token_digest=#{token_digest} ip=#{request.ip}"
    error!({ error: e.message, code: e.code }, 410)
  rescue MagicLinks::Verifier::AlreadyUsedError => e
    logger.warn "[MagicLink] already_used token_digest=#{token_digest} ip=#{request.ip}"
    error!({ error: e.message, code: e.code }, 409)
  rescue MagicLinks::Verifier::UserNotFoundError => e
    logger.warn "[MagicLink] user_not_found token_digest=#{token_digest} ip=#{request.ip}"
    error!({ error: e.message, code: e.code }, 404)
  rescue MagicLinks::Verifier::NotFoundError => e
    logger.warn "[MagicLink] not_found token_digest=#{token_digest} ip=#{request.ip}"
    error!({ error: e.message, code: e.code }, 404)
  rescue MagicLinks::Verifier::Error => e
    logger.error "[MagicLink] verifier_error code=#{e.code} token_digest=#{token_digest}"
    error!({ error: e.message, code: e.code }, 400)
  rescue ActiveRecord::RecordInvalid => e
    logger.error "[MagicLink] verifier_invalid token_digest=#{token_digest} errors=#{e.record.errors.full_messages.join(', ')}"
    error!({ error: 'Unable to consume magic link.', code: 'validation_error' }, 422)
  end

  #
  # Poll for the current status of a pending magic link
  #
  desc 'Magic link status lookup'
  params do
    requires :token, type: String, desc: 'Magic link token'
  end
  get '/auth/magic-link/status' do
    ensure_magic_link_available!

    token_param = params[:token].to_s
    token_digest = token_param.present? ? MagicLinkRequest.digest_for(token_param) : nil
    request_record = token_digest.present? ? MagicLinkRequest.find_by(token_digest: token_digest) : nil

    status_value =
      if request_record.nil?
        'invalid'
      elsif request_record.consumed_at?
        'consumed'
      elsif request_record.expired?
        'expired'
      else
        'pending'
      end

    response = { status: status_value }
    response[:expires_at] = request_record.expires_at.iso8601 if request_record&.expires_at

    present response, with: Grape::Presenters::Presenter
  end

  #
  # Returns the current auth signout URL
  #
  desc 'Authentication signout URL'
  get '/auth/signout_url' do
    response = {}
    response[:auth_signout_url] =
      if aaf_auth? && Doubtfire::Application.config.aaf[:auth_signout_url].present?
        Doubtfire::Application.config.aaf[:auth_signout_url]
      elsif saml_auth? && Doubtfire::Application.config.saml[:idp_sso_signout_url].present?
        Doubtfire::Application.config.saml[:idp_sso_signout_url]
      end
    present response, with: Grape::Presenters::Presenter
  end

  #
  # Update the expiry of an existing authentication token
  #
  desc 'Allow tokens to be updated',
       {
         headers:
         {
           "username" =>
           {
             description: "User username",
             required: true
           },
           "auth_token" =>
           {
             description: "The user's temporary auth token",
             required: true
           }
         }
       }
  params do
    optional :remember, type: Boolean, desc: 'User has requested to remember login', default: false
  end
  put '/auth' do
    token_param = headers['auth-token'] || headers['Auth-Token'] || params['Auth-Token']
    user_param = headers['username'] || headers['Username'] || params['Username'] || params['username']

    error!({ error: 'Invalid token/username.' }, 404) if token_param.nil? || user_param.nil?

    logger.info "Update token #{token_param} from #{request.ip} for #{user_param}"

    # Find user
    user = User.find_by_username(user_param)
    token = user.token_for_text?(token_param) unless user.nil?
    remember = params[:remember] || false

    # Token does not match user
    if token.nil? || user.nil? || user.username != user_param
      error!({ error: 'Invalid token.' }, 404)
    else
      token.extend_token remember if token.auth_token_expiry > Time.zone.now

      # Return extended auth token
      present :auth_token, token.authentication_token
    end
  end

  #
  # Sign out
  #
  desc 'Sign out',
       {
         headers:
         {
           "username" =>
           {
             description: "User username",
             required: true
           },
           "auth_token" =>
           {
             description: "The user's temporary auth token",
             required: true
           }
         }
       }
  delete '/auth' do
    user = User.find_by_username(headers['username'] || headers['Username'])
    token = user.token_for_text?(headers['auth-token'] || headers['Auth-Token']) unless user.nil?

    if token.present?
      logger.info "Sign out #{user.username} from #{request.ip}"
      token.destroy!
    end

    present nil
  end
end
