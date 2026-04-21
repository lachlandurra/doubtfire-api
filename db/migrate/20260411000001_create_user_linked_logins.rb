class CreateUserLinkedLogins < ActiveRecord::Migration[7.1]
  def change
    create_table :user_linked_logins do |t|
      t.references :user, null: false, foreign_key: true
      t.string :provider, null: false
      t.string :provider_identifier, null: false
      t.timestamps
    end

    add_index :user_linked_logins, [:provider, :provider_identifier], unique: true
  end
end
