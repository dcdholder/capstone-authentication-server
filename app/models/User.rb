class User < ApplicationRecord
	has_many :device, :through => :device_user	
end
