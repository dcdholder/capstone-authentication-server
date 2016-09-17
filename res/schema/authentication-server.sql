--TODO: change field types to correct ones

/* This generates the tables needed for centralized authentication of the device. */

CREATE DATABASE bleDevice;

USE bleDevice

-- currently will only have two entries - the userId and deviceId salts
CREATE TABLE globalSalts (
	fieldName VARCHAR(100),
	salt      INT,
	
	PRIMARY KEY (fieldName)
);

CREATE TABLE deviceOwnership (
	deviceIdHash INT,
	ownerIdHash  INT,
	
	PRIMARY KEY (deviceIdHash) -- each device can have only one owner
);

/* A separate cipher is needed for each user of the device, 
   since the cipher is generated based on each authenticated user's password */

CREATE TABLE deviceUsership (
	deviceIdHash    INT,
	userIdHash      INT,
	ownerIdHash     INT,
	deviceTagCipher VARBINARY,
	
	PRIMARY KEY (deviceIdHash, userIdHash) -- each device can have more than one user
);

-- must have admin credentials to add new device hashes
-- admin access would probably be restricted to the local network for security reasons
CREATE TABLE admins (
	adminIdHash  INT,
	adminIdSalt  INT,
	passwordHash INT,
	passwordSalt INT,
	
	PRIMARY KEY (adminIdHash)
);

CREATE TABLE users (
	userIdHash       INT,
	passwordHash     INT,
	passwordSalt     INT,
	keygenSalt       INT,
	publicKey        VARBINARY,
	privateKeyCipher VARBINARY, -- yeah I know
	
	PRIMARY KEY (userIdHash)
);

-- unsafe; device ID and hash must use a very large number of bits if we choose to use a global salt
CREATE TABLE devices (
	deviceIdHash INT,
	
	PRIMARY KEY (deviceIdHash)
);
