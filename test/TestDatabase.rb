require 'test/unit'
require_relative '../lib/Database.rb'

class TestDatabase < Test::Unit::TestCase

	TEST_USERNAME             = "sensfan69"    #should be a valid username
	TEST_USERNAME_WITH_SPACES = "sens fan 69"
	TEST_PASSWORD             = "password_123" #should be a valid password
	TEST_PASSWORD_WITH_SPACES = "password 123"

	def truncateToCharacterLimit(string,maxLength)
		if string.length<maxLength
			return string
		else
			return string[0...maxLength]
		end
	end

	def padToMinimumCharacterLimit(string,minLength)
		if string.length>minLength
			return string
		else
			return string + "A" * (minLength - string.length)
		end
	end

	def setup #TODO: figure out how to only run this once
		assert_nothing_raised do
			Database.confirmIdFormatCorrect(TEST_USERNAME)
			Database.confirmPasswordFormatCorrect(TEST_PASSWORD)
		end
	end

	def testUserIdValidLength
		tooShortUsername = truncateToCharacterLimit(TEST_USERNAME,Database::MIN_USERNAME_LENGTH-1)
		tooLongUsername  = padToMinimumCharacterLimit(TEST_USERNAME,Database::MAX_USERNAME_LENGTH+1)
		
		assert_raise do
			Database.confirmIdFormatCorrect(tooLongUsername)
			Database.confirmIdFormatCorrect(tooShortUsername)
		end
	end
	
	def testUserIdInvalidCharacters #just check for spaces for now
		assert_raise do
			Database.confirmIdFormatCorrect(TEST_USERNAME_WITH_SPACES)
		end
	end
	
	def testConfirmPasswordValidLength
		tooShortPassword = truncateToCharacterLimit(TEST_PASSWORD,Database::MIN_PASSWORD_LENGTH-1)
		tooLongPassword  = padToMinimumCharacterLimit(TEST_USERNAME,Database::MAX_PASSWORD_LENGTH+1) 
		
		assert_raise do
			Database.confirmPasswordFormatCorrect(tooLongUsername)
			Database.confirmPasswordFormatCorrect(tooShortUsername)
		end
	end
	
	def testPasswordInvalidCharacters #just check for spaces for now
		assert_raise do
			Database.confirmIdFormatCorrect(TEST_PASSWORD_WITH_SPACES)
		end
	end

end
