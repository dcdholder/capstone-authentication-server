require_relative './TestDatabase.rb'
require_relative './TestCryptography.rb'
require_relative './TestIntegration.rb'

class AllTests < Test::Unit::TestSuite
	def self.suite
		suite = Test::Unit::TestSuite.new
		suite << TestDatabase.suite
		suite << TestCryptography.suite
		suite << TestIntegration.suite
	end
end
