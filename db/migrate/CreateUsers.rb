class CreateUsers < ActiveRecord::Migration[5.0]
	def self.up
		create_table :users do |table|
			table.string :type
			
			table.binary :salt
			table.binary :username_digest
			table.binary :credentials_digest
			
			table.string :public_key_pem
			table.string :private_key_cipher_pem
		end
	end
end
