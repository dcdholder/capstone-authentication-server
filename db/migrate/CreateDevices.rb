class CreateDevices < ActiveRecord::Migration[5.0]
	def self.up
		create_table :devices do |table|
			table.binary :device_id_digest
		end
	end
end
