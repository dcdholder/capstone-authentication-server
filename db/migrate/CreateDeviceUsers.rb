class CreateDeviceUsers < ActiveRecord::Migration[5.0]
	def self.up
		create_table :device_users do |table|
			table.string :type
			
			table.binary :username_digest
			table.binary :device_id_digest
			
			table.binary :device_tag_cipher
			table.binary :device_id_cipher
		end
	end		
end
