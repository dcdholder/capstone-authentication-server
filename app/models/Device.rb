class Device < ApplicationRecord
	belongs_to :user, :through => :owner
	has_many   :user, :through => :nonowner
end
