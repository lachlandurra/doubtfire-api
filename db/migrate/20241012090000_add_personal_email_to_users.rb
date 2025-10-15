class AddPersonalEmailToUsers < ActiveRecord::Migration[7.0]
  def change
    add_column :users, :personal_email, :string
    add_column :users, :personal_email_verified_at, :datetime

    add_index :users, :personal_email, unique: true
  end
end
