class CreateCommonSalts < ActiveRecord::Migration[5.0]
	def self.up
		create_table :common_salts do |table|
			table.string :type
			
			table.binary :salt
		end
	end
end
