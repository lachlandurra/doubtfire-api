class UserLinkedLogin < ApplicationRecord
  belongs_to :user

  validates :provider, presence: true
  validates :provider_identifier, presence: true, uniqueness: { scope: :provider }
end
