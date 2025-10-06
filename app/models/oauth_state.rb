# frozen_string_literal: true

class OauthState < ApplicationRecord
  EXPIRATION_WINDOW = 15.minutes

  belongs_to :user, optional: true, inverse_of: :oauth_states

  validates :token, presence: true, uniqueness: true
  validates :purpose, presence: true
  validates :provider, presence: true

  scope :expired, ->(ttl = EXPIRATION_WINDOW) { where('created_at < ?', Time.zone.now - ttl) }

  def self.cleanup_expired!(ttl: EXPIRATION_WINDOW)
    expired(ttl).delete_all
  end
end
