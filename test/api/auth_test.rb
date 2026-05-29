require 'test_helper'

class AuthTest < ActiveSupport::TestCase
  include Rack::Test::Methods
  include TestHelpers::AuthHelper
  include TestHelpers::JsonHelper

  def app
    Rails.application
  end

  def with_auth_config(auth_method: nil, oauth_providers: nil, oauth_enabled: nil, saml: :__no_change__)
    config = Doubtfire::Application.config

    original_auth_method = config.auth_method
    original_oauth_providers = if config.oauth_providers.present?
                                 config.oauth_providers.deep_dup
                               else
                                 ActiveSupport::HashWithIndifferentAccess.new
                               end
    original_oauth_enabled = config.oauth_enabled
    saml_accessor_defined = config.respond_to?(:saml) && config.respond_to?(:saml=)
    original_saml = saml_accessor_defined ? config.saml&.dup : nil
    created_saml_accessor = false

    config.auth_method = auth_method if auth_method
    unless oauth_providers.nil?
      config.oauth_providers = oauth_providers.with_indifferent_access
    end
    unless oauth_enabled.nil?
      config.oauth_enabled = oauth_enabled
    end
    if saml != :__no_change__
      unless config.respond_to?(:saml=)
        config.singleton_class.attr_accessor :saml
        created_saml_accessor = true
      end
      config.saml = saml.nil? ? nil : saml.with_indifferent_access
    end

    yield
  ensure
    config.auth_method = original_auth_method
    config.oauth_providers = original_oauth_providers
    config.oauth_enabled = original_oauth_enabled
    if config.respond_to?(:saml=)
      if saml_accessor_defined
        config.saml = original_saml
      elsif created_saml_accessor
        config.singleton_class.send(:remove_method, :saml=)
        config.singleton_class.send(:remove_method, :saml)
      end
    end
  end

  def oauth_provider_config_stub
    {
      google: {
        name: 'Google',
        client_id: 'client-id',
        client_secret: 'secret',
        redirect_uri: 'https://example.com/google/callback',
        scope: 'openid,email,profile',
        icon: 'google',
        priority: 1
      },
      github: {
        name: 'GitHub',
        client_id: 'client-id',
        client_secret: 'secret',
        redirect_uri: 'https://example.com/github/callback',
        scope: 'read:user,user:email',
        icon: 'github',
        priority: 2
      }
    }
  end

  def saml_config_stub
    {
      SAML_metadata_url: nil,
      assertion_consumer_service_url: 'https://example.com/api/auth/jwt',
      entity_id: 'https://example.com/sp',
      idp_sso_target_url: 'https://idp.example.com/sso',
      idp_sso_signout_url: 'https://idp.example.com/logout',
      idp_sso_cert: '-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----',
      idp_name_identifier_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    }
  end

  # --------------------------------------------------------------------------- #
  # --- Endpoint testing for:
  # ------- /api/auth.json
  # ------- POST PUT DELETE

  # --------------------------------------------------------------------------- #
  # POST tests

  # Test POST for new authentication token
  def test_auth_post
    data_to_post = {
      username: 'aadmin',
      password: 'password'
    }
    # Get response back for logging in with username 'aadmin' password 'password'
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body
    expected_auth = User.first

    # Check that response contains a user.
    assert actual_auth.key?('user'), 'Expect response to have a user'
    assert actual_auth.key?('auth_token'), 'Expect response to have a auth token'

    response_user_data = actual_auth['user']

    # Check that the returned user has the required details.
    # These match the model object... so can compare in loops
    user_keys = %w(id email first_name last_name username nickname receive_task_notifications receive_portfolio_notifications receive_feedback_notifications opt_in_to_research has_run_first_time_setup)

    # Check the returned user matches the expected database value
    assert_json_matches_model(expected_auth, response_user_data, user_keys)

    # Check other values returned
    assert_equal expected_auth.role.name, response_user_data['system_role'], 'Roles match'

    token = User.first.token_for_text? actual_auth['auth_token'], :general
    assert token.present?
    assert_equal 'general', token.token_type

    # User has the token - count of matching tokens for that user is 1
    assert_equal 1, expected_auth.auth_tokens.select{|t| t.authentication_token == actual_auth['auth_token']}.count
  end

  # Test auth when username is invalid
  def test_fail_username_auth
    data_to_post = {
      username: 'aadmin123',
      password: 'password'
    }
    # Get response back for logging in with username 'aadmin' password 'password'
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body

    # Check response body doesn't return 'user' and 'auth_token' values
    refute actual_auth.key?('user'), 'User not expected if auth fails'
    refute actual_auth.key?('auth_token'), 'Auth token not expected if auth fails'

    # 401 response code means invalid username / password
    assert_equal 401, last_response.status
    assert actual_auth.key? 'error'
  end

  # Test auth when password is invalid
  def test_fail_password_auth
    data_to_post = {
      username: 'aadmin',
      password: 'password1'
    }

    # Get response back for logging in with username 'aadmin' password 'password1'
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body

    # Check response body doesn't return 'user' and 'auth_token' values
    refute actual_auth.key?('user'), 'User not expected if auth fails'
    refute actual_auth.key?('auth_token'), 'Auth token not expected if auth fails'

    assert actual_auth.key? 'error'
  end

  # Test auth with empty request body
  def test_fail_empty_request
    data_to_post = ""

    # Post empty data
    post_json '/api/auth.json', data_to_post
    actual_auth = last_response_body

    # Check response body doesn't return 'user' and 'auth_token' values
    refute actual_auth.key?('user'), 'User not expected if auth fails'
    refute actual_auth.key?('auth_token'), 'Auth token not expected if auth fails'

    # 400 response code means missing username and password
    assert_equal 400, last_response.status
    assert actual_auth.key?('error'), actual_auth.inspect
  end

  def test_auth_with_temporary_login_token
    with_auth_config(auth_method: :database, oauth_enabled: true) do
      user = FactoryBot.create(:user)
      login_token = user.generate_temporary_authentication_token!

      post_json '/api/auth.json', {
        username: user.username,
        auth_token: login_token.authentication_token,
        remember: true
      }

      assert_equal 201, last_response.status
      body = last_response_body

      assert body.key?('user'), body.inspect
      assert body.key?('auth_token'), body.inspect
      assert_equal user.id, body['user']['id']
      refute_equal login_token.authentication_token, body['auth_token']

      assert_raises(ActiveRecord::RecordNotFound) { login_token.reload }

      user.reload
      assert_nil user.token_for_text?(login_token.authentication_token, :login)
      exchanged_token = user.token_for_text?(body['auth_token'], :general)
      assert exchanged_token.present?
      assert_equal 'general', exchanged_token.token_type
    end
  end

  # Test auth with tutor role
  def test_auth_roles
    post_tests = [
      {
        expect: Role.admin,
        post: {
          username: 'aadmin',
          password: 'password'
        }
      },
      {
        expect: Role.convenor,
        post: {
          username: 'aconvenor',
          password: 'password'
        }
      },
      {
        expect: Role.tutor,
        post: {
          username: 'atutor',
          password: 'password'
        }
      },
      {
        expect: Role.student,
        post: {
          username: 'astudent',
          password: 'password'
        }
      }
    ]

    post_tests.each do |test_data|
      # Get response back for logging in with above data
      post_json '/api/auth.json', test_data[:post]
      actual_auth = last_response_body

      assert actual_auth['user'], last_response_body.inspect
      assert_equal test_data[:expect].name, actual_auth['user']['system_role'], 'Roles match expected role'
    end
  end

  # End POST tests
  # --------------------------------------------------------------------------- #

  # --------------------------------------------------------------------------- #
  # PUT tests

  # Test put for authentication token
  def test_auth_put
    add_auth_header_for(user: User.first)
    put_json "/api/auth", nil

    actual_auth = last_response_body['auth_token']
    expected_auth = auth_token
    # Check to see if the response auth token matches the auth token that was sent through in put
    assert_equal expected_auth, actual_auth
  end

  def test_auth_method_without_oauth_in_database_mode
    with_auth_config(auth_method: :database, oauth_providers: {}, oauth_enabled: false) do
      header 'Host', 'localhost'
      get '/api/auth/method'

      assert_equal 200, last_response.status
      body = last_response_body

      assert_equal 'database', body['method']
      refute body.key?('oauth_enabled'), body.inspect
      refute body.key?('oauth_providers'), body.inspect
      header 'Host', nil
    end
  end

  def test_auth_method_without_oauth_in_saml_mode
    with_auth_config(auth_method: :saml, oauth_providers: {}, oauth_enabled: false, saml: saml_config_stub) do
      header 'Host', 'localhost'
      get '/api/auth/method'

      assert_equal 200, last_response.status
      body = last_response_body

      assert_equal 'saml', body['method']
      assert body.key?('redirect_to'), body.inspect
      refute body.key?('oauth_enabled'), body.inspect
      header 'Host', nil
    end
  end

  def test_auth_method_with_multiple_oauth_providers
    with_auth_config(auth_method: :database, oauth_providers: oauth_provider_config_stub, oauth_enabled: true) do
      header 'Host', 'localhost'
      get '/api/auth/method'

      assert_equal 200, last_response.status
      body = last_response_body

      assert_equal true, body['oauth_enabled']
      assert_equal %w[google github], body['oauth_providers'].map { |provider| provider['key'] }
    ensure
      header 'Host', nil
    end
  end

  def test_link_endpoint_returns_provider_request_url_for_github
    with_auth_config(auth_method: :database, oauth_providers: oauth_provider_config_stub, oauth_enabled: true) do
      user = FactoryBot.create(:user)
      add_auth_header_for(user: user)
      header 'Host', 'localhost'

      post_json '/api/auth/oauth/github/link', {}

      assert_includes [200, 201], last_response.status
      body = last_response_body

      match = body["redirect_to"].match(%r{^/api/auth/oauth/github[?]oauth_state_token=([^&]+)})
      assert match, body['redirect_to']

      state = OauthState.find_by(token: match[1])
      assert_equal Api::OauthController::PURPOSE_LINK, state.purpose
      assert_equal user.id, state.user_id
    ensure
      clear_auth_header
      header 'Host', nil
    end
  end

  def test_oauth_failure_redirect_uses_state_redirect_path
    location = Api::OauthController.new.send(
      :failure_redirect_url,
      "google",
      "no_matching_account",
      redirect_path: "http://localhost:4200/sign_in"
    )

    uri = URI.parse(location)
    assert_equal "http", uri.scheme
    assert_equal "localhost", uri.host
    assert_equal 4200, uri.port
    assert_equal "/sign_in", uri.path

    params = Rack::Utils.parse_nested_query(uri.query)
    assert_equal "no_matching_account", params["oauth_error"]
    assert_equal "OAuth sign-in failed", params["oauth_error_message"]
  end

  def test_unlink_rejected_when_identity_is_last_sign_in_method
    with_auth_config(auth_method: :saml_oauth, oauth_providers: oauth_provider_config_stub, oauth_enabled: true) do
      user = FactoryBot.create(:user, login_id: 'oauthuser')
      identity = user.link_oauth_identity!(provider: 'google', uid: 'uid-1', raw_info: {})

      add_auth_header_for(user: user)
      header 'Host', 'localhost'
      delete_json '/api/auth/oauth/google'

      assert_equal 422, last_response.status
      body = last_response_body
      assert_equal 'You must add another sign-in method before unlinking this provider.', body['error']
      assert OauthIdentity.exists?(identity.id)

      clear_auth_header
      header 'Host', nil
    end
  end

  def test_unlink_allowed_when_user_has_saml_identity
    with_auth_config(auth_method: :saml_oauth, oauth_providers: oauth_provider_config_stub, oauth_enabled: true) do
      user = FactoryBot.create(:user, login_id: 'user@example.com')
      identity = user.link_oauth_identity!(provider: 'google', uid: 'uid-2', raw_info: {})

      add_auth_header_for(user: user)
      header 'Host', 'localhost'
      delete_json '/api/auth/oauth/google'

      assert_includes [200, 204], last_response.status
      if last_response.status == 200
        assert_nil last_response_body
      else
        assert_equal '', last_response.body
      end
      refute OauthIdentity.exists?(identity.id)

      clear_auth_header
      header 'Host', nil
    end
  end

  def test_auth_using_query_string
    put_json "/api/auth?Username=#{User.first.username}&Auth-Token=#{auth_token(User.first)}", nil
    assert_equal 200, last_response.status, last_response_body
  end

  # Test invalid authentication token
  def test_fail_auth_put
    # Override data to set custom username or token in header
    # Add authentication token to header
    add_auth_header_for(user: User.first, auth_token: '1234')
    put_json "/api/auth", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 404 response code means invalid token
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end

  # Test invalid username for valid authentication token
  def test_fail_username_put
    # Add authentication token to header
    add_auth_header_for(user: User.first, username: 'acain123')
    put_json "/api/auth", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 404 response code means invalid token
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end

  # Test valid username for empty authentication token
  def test_fail_empty_authKey_put
    # Add authentication token to header
    add_auth_header_for(user: User.first)

    # Overwrite header for empty auth_token
    header 'auth_token',''

    put_json "/api/auth/", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 404 response code means invalid token
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end

  # Test empty request
  def test_fail_empty_body_put
    put_json "/api/auth", nil
    actual_auth = last_response_body
    expected_auth = auth_token

    # 400 response code means empty body
    assert_equal 404, last_response.status

    # Check to see if the response is invalid
    assert actual_auth.key? 'error'
  end
  # # End PUT tests
  # # --------------------------------------------------------------------------- #

  # # --------------------------------------------------------------------------- #
  # # DELETE tests

  # Test for deleting authentication token
  def test_auth_delete
    # Add authentication token to header
    add_auth_header_for(user: User.first)

    delete "/api/auth", nil
    # 204 response code means success!
    assert_equal 204, last_response.status
  end

  def test_token_signout_works_with_multiple
    user = FactoryBot.create(:user)
    # Create 2 auth tokens
    t1 = user.generate_authentication_token!
    t2 = user.generate_authentication_token!

    # Set custom headers for request
    # Add authentication token to header
    add_auth_header_for(username: user.username, auth_token: t1.authentication_token)

    # Sign out one
    delete "/api/auth.json"

    t2.reload
    refute t2.destroyed?

    assert_raises(ActiveRecord::RecordNotFound) { t1.reload }
  end
  # End DELETE tests
  # --------------------------------------------------------------------------- #

  # # --------------------------------------------------------------------------- #
  # # SCORM auth test

  def test_scorm_auth
    admin = FactoryBot.create(:user, :admin)

    add_auth_header_for(user: admin)

    # All users can access scorm resources
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert_equal 1, admin.auth_tokens.where(token_type: :scorm).count

    student = FactoryBot.create(:user, :student)

    student.auth_tokens.where(token_type: :scorm).destroy_all

    add_auth_header_for(user: student)

    # When user is authorised and no prior scorm tokens exist
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert last_response_body["scorm_auth_token"]
    assert 2, student.auth_tokens.where(token_type: :scorm).count

    first_token = last_response_body["scorm_auth_token"]

    add_auth_header_for(user: student)

    # When previous valid scorm token exists
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert last_response_body["scorm_auth_token"] == first_token

    old_token = student.auth_tokens.find_by(token_type: :scorm)
    old_token.auth_token_expiry = Time.zone.now - 1.day
    old_token.save!

    add_auth_header_for(user: student)

    # When previous expired scorm token exists
    get "api/auth/scorm"
    assert_equal 200, last_response.status
    assert last_response_body["scorm_auth_token"] != first_token
    assert_raises ActiveRecord::RecordNotFound do
      student.auth_tokens.find(old_token.id)
    end
  end

  # End SCORM auth test
  # --------------------------------------------------------------------------- #

  def test_login_token
    unit = FactoryBot.create :unit, with_students: false
    user = unit.main_convenor_user

    token = user.generate_temporary_authentication_token!

    add_auth_header_for(user: user, auth_token: token)

    get 'api/units'

    assert 403, last_response.status

    post 'api/auth'
  ensure
    unit.destroy
  end

  def test_scorm_token
    unit = FactoryBot.create :unit, with_students: false
    user = unit.main_convenor_user

    token = user.generate_scorm_authentication_token!

    add_auth_header_for(user: user, auth_token: token)

    get '/api/units'

    assert 403, last_response.status
  ensure
    unit.destroy
  end
end
