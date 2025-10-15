class CreateMagicLinkRequests < ActiveRecord::Migration[7.0]
  def change
    create_table :magic_link_requests do |t|
      t.string :token_digest, null: false
      t.string :email, null: false
      t.references :user, foreign_key: true, null: true
      t.string :purpose, null: false, default: 'login'
      t.datetime :sent_at, null: false
      t.datetime :expires_at, null: false
      t.datetime :consumed_at
      t.string :request_ip, limit: 45
      t.string :user_agent, limit: 512
      t.json :metadata

      t.timestamps
    end

    add_index :magic_link_requests, :token_digest, unique: true
    add_index :magic_link_requests, :email
    add_index :magic_link_requests, :expires_at
    add_index :magic_link_requests, [:email, :sent_at]
    add_index :magic_link_requests, [:request_ip, :sent_at]
  end
end
