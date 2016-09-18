class DeviceUser < ApplicationRecord
	belongs_to :user
	belongs_to :device
end
