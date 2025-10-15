# Settings specified here will take precedence over those in config/application.rb
Doubtfire::Application.configure do
  # The test environment is used exclusively to run your application's
  # test suite. You never need to work with it otherwise. Remember that
  # your test database is "scratch space" for the test suite and is wiped
  # and recreated between test runs. Don't rely on the data there!
  config.cache_classes = true

  # Configure static asset server for tests with Cache-Control for performance
  config.serve_static_files = true
  config.static_cache_control = 'public, max-age=3600'

  # Eager
  config.eager_load = false

  # Show full error reports and disable caching
  config.consider_all_requests_local       = true
  config.action_controller.perform_caching = false

  # Raise exceptions instead of rendering exception templates
  config.action_dispatch.show_exceptions = false

  # Disable request forgery protection in test environment
  config.action_controller.allow_forgery_protection = false

  # Tests can exercise SMTP-specific code paths by toggling delivery method via env vars.
  delivery_method = (ENV['DF_MAIL_DELIVERY_METHOD'] || 'test').to_sym
  config.action_mailer.delivery_method = delivery_method
  config.action_mailer.perform_deliveries = delivery_method != :test

  if delivery_method == :smtp
    # Reuse the same SMTP shape as production so behaviour stays consistent.
    config.action_mailer.smtp_settings = {
      address: ENV.fetch('DF_SMTP_ADDRESS', 'localhost'),
      port: ENV.fetch('DF_SMTP_PORT', 25),
      domain: ENV.fetch('DF_SMTP_DOMAIN', nil),
      user_name: ENV.fetch('DF_SMTP_USERNAME', nil),
      password: ENV.fetch('DF_SMTP_PASSWORD', nil),
      authentication: ENV.fetch('DF_SMTP_AUTH', ENV.fetch('DF_SMTP_AUTHENTICATION', 'plain')),
      enable_starttls_auto: ENV.fetch('DF_SMTP_ENABLE_STARTTLS', 'true') != 'false'
    }
  end

  # Print deprecation notices to the stderr
  config.active_support.deprecation = :stderr

  # Set deterministic randomness, source: https://github.com/stympy/faker#deterministic-random
  Faker::Config.random = Random.new(77)

  # Logging level (:debug, :info, :warn, :error, :fatal)
  config.log_level = :warn

  config.active_record.encryption.key_derivation_salt = ENV['DF_ENCRYPTION_KEY_DERIVATION_SALT'] || 'U9jurHMfZbMpzlbDTMe5OSAhUJYHla9Z'
  config.active_record.encryption.deterministic_key = ENV['DF_ENCRYPTION_KEY_DERIVATION_SALT'] || 'zYtzYUlLFaWdvdUO5eIINRT6ZKDddcgx'
  config.active_record.encryption.primary_key = ENV['DF_ENCRYPTION_KEY_DERIVATION_SALT'] || '92zoF7RJaQ01JEExOgHbP9bRWldNQUz5'

  # Set turn it in environment
  ENV.store('TCA_SIGNING_KEY', 'test')
  ENV.store('TII_ENABLED', '1')
  ENV.store('TCA_API_KEY', '1234')
  ENV.store('TCA_HOST', 'localhost')
end
