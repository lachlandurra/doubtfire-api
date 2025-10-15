# frozen_string_literal: true

require 'digest'

class MagicLinkRequest < ApplicationRecord
  PURPOSE_LOGIN = 'login'

  belongs_to :user, optional: true

  attribute :metadata, :json, default: {}

  validates :token_digest, presence: true, uniqueness: true
  validates :email, presence: true, format: { with: User::EMAIL_REGEX }
  validates :purpose, presence: true

  before_validation :normalise_email
  before_validation :ensure_metadata_hash

  scope :pending, -> { where(consumed_at: nil) }
  scope :expired, -> { where.not(expires_at: nil).where('expires_at <= ?', Time.zone.now) }
  scope :consumable, -> { pending.where('expires_at > ?', Time.zone.now) }

  def consume!(updates = {})
    raise AlreadyConsumedError, 'Magic link already consumed.' if consumed_at?
    raise ExpiredError, 'Magic link has expired.' if expired?

    update!(updates.merge(consumed_at: Time.zone.now))
  end

  def expired?
    expires_at.present? && expires_at <= Time.zone.now
  end

  def self.digest_for(raw_token)
    Digest::SHA256.hexdigest(raw_token.to_s)
  end

  def self.cleanup_expired!
    expired.delete_all
  end

  class AlreadyConsumedError < StandardError; end
  class ExpiredError < StandardError; end

  private

  def normalise_email
    self.email = email.to_s.downcase.strip if email.present?
  end

  def ensure_metadata_hash
    self.metadata = {} unless metadata.is_a?(Hash)
  end
end
