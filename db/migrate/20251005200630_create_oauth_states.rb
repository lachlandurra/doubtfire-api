class CreateOauthStates < ActiveRecord::Migration[7.1]
  def change
    create_table :oauth_states do |t|
      t.string :token, null: false
      t.string :purpose, null: false
      t.references :user, null: true, foreign_key: true
      t.string :provider, null: false
      t.string :redirect_path
      t.string :code_verifier
      t.timestamps

      t.index :token, unique: true
      t.index :created_at, name: 'index_oauth_states_on_created_at_for_expiry'
    end
  end
end
