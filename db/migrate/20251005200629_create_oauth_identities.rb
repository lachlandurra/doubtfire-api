class CreateOauthIdentities < ActiveRecord::Migration[7.1]
  def change
    raw_info_column_type = json_column_type
    raw_info_options = { null: false }
    raw_info_options[:default] = {} if raw_info_column_type == :jsonb

    create_table :oauth_identities do |t|
      t.references :user, null: false, foreign_key: true
      t.string :provider, null: false
      t.string :uid, null: false
      t.string :verified_email
      t.public_send(raw_info_column_type, :raw_info, **raw_info_options)
      t.text :refresh_token_encrypted
      t.datetime :last_used_at
      t.timestamps

      t.index [:provider, :uid], unique: true
    end
  end

  private

  def json_column_type
    adapter = connection.adapter_name.downcase
    adapter.include?('postgres') ? :jsonb : :json
  end
end
