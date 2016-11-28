/* This generates the tables needed for centralized authentication of the device. */

DROP DATABASE bleDevice;

CREATE DATABASE bleDevice;

USE bleDevice

/*
-- currently will only have two entries - the userId and deviceId salts
CREATE TABLE globalSalts (
	fieldName VARCHAR(100),
	salt      BLOB,
	
	PRIMARY KEY (fieldName)
);
*/

CREATE TABLE deviceOwnership (
	deviceIdHash TEXT,
	ownerIdHash  TEXT
	
	-- PRIMARY KEY (deviceIdHash) -- each device can have only one owner
);

/* A separate cipher is needed for each user of the device, 
   since the cipher is generated based on each authenticated user's password */

CREATE TABLE deviceUsership (
	deviceIdHash    TEXT,
	userIdHash      TEXT,
	ownerIdHash     TEXT,
	deviceIdCipher  TEXT,
	deviceTagCipher TEXT,
	userIdCipher    TEXT -- encrypted using the owner's credentials
	
	-- PRIMARY KEY (deviceIdHash, userIdHash) -- each device can have more than one user
);

-- must have admin credentials to add new device hashes
-- admin access would probably be restricted to the local network for security reasons
CREATE TABLE admins (
	adminIdHash  TEXT,
	adminIdSalt  TEXT,
	passwordHash TEXT,
	passwordSalt TEXT
	
	-- PRIMARY KEY (adminIdHash)
);

CREATE TABLE users (
	userIdHash       TEXT,
	passwordHash     TEXT,
	passwordSalt     TEXT,
	keygenSalt       TEXT,
	publicKey        TEXT,
	privateKeyCipher TEXT -- yeah I know
	
	-- PRIMARY KEY (userIdHash)
);

-- unsafe; device ID and hash must use a very large number of bits if we choose to use a global salt
CREATE TABLE devices (
	deviceIdHash TEXT
	
	-- PRIMARY KEY (deviceIdHash)
);
