# frozen_string_literal: true

require 'json'

class OauthIdentity < ApplicationRecord
  belongs_to :user, inverse_of: :oauth_identities

  serialize :raw_info, coder: JSON

  before_validation :ensure_raw_info_present

  validates :user, presence: true
  validates :provider, presence: true
  validates :uid, presence: true, uniqueness: { scope: :provider }

  private

  def ensure_raw_info_present
    self.raw_info = {} if raw_info.nil?
  end
end
