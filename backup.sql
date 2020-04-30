PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE role (
	id INTEGER NOT NULL, 
	name VARCHAR(80), 
	description VARCHAR(255), 
	PRIMARY KEY (id), 
	UNIQUE (name)
);
INSERT INTO "role" VALUES(1,'admin','super user');
INSERT INTO "role" VALUES(2,'finance','Can view/action settlements');
CREATE TABLE "user" (
	id INTEGER NOT NULL, 
	first_name VARCHAR(255), 
	last_name VARCHAR(255), 
	email VARCHAR(255), 
	password VARCHAR(255), 
	active BOOLEAN, 
	confirmed_at DATETIME, max_settlements_per_month INTEGER, 
	PRIMARY KEY (id), 
	UNIQUE (email), 
	CHECK (active IN (0, 1))
);
INSERT INTO "user" VALUES(1,NULL,NULL,'dnewton@redratclothing.co.nz','$pbkdf2-sha512$25000$tzbmXCvl/P.fs7YWonRO6Q$sMxqJsUHOApKCRJBl6LkAKs6L5AEnMoHvExfioegX3KkeOEpcZBbppNemfN.ES9H91JmGmrCmTkCSymW5dQFbg',1,'2019-11-27 23:36:01.920551',3);
INSERT INTO "user" VALUES(2,NULL,NULL,'djpnewton@gmail.com','$pbkdf2-sha512$25000$09p7zxkDQOj9nxPinPPe.w$RKclkswcDs1y1P1MyS62OKzt6G6prDMaSihmEfO1tGOnAOvYFRdyJn6I5kuxY8h8G/ezK1tDgHpWG6s0wIjeBw',1,'2019-11-27 19:59:34.211064',NULL);
CREATE TABLE roles_users (
	user_id INTEGER, 
	role_id INTEGER, 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	FOREIGN KEY(role_id) REFERENCES role (id)
);
INSERT INTO "roles_users" VALUES(1,1);
INSERT INTO "roles_users" VALUES(2,2);
CREATE TABLE api_key (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	date DATETIME NOT NULL, 
	name VARCHAR(255) NOT NULL, 
	token VARCHAR(255) NOT NULL, 
	nonce INTEGER NOT NULL, 
	secret VARCHAR(255) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	UNIQUE (token)
);
INSERT INTO "api_key" VALUES(1,1,'2019-11-21 14:36:34.294659','test','ce8b59998025b9ec',1582786777,'7a5e54794184c2e4e88ae9acf94f2d97');
INSERT INTO "api_key" VALUES(2,2,'2019-11-28 08:59:58.018453','test','de5482bdb8009ad6',1574897373,'e7958b293f4b608e0a816862c4117217');
CREATE TABLE tx_notification (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	date DATETIME, 
	txid VARCHAR(255), 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	UNIQUE (txid)
);
CREATE TABLE claim_code (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	date DATETIME, 
	token VARCHAR(255) NOT NULL, 
	secret VARCHAR(255), 
	amount INTEGER, 
	address VARCHAR(255), 
	status VARCHAR(255), 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	UNIQUE (token)
);
INSERT INTO "claim_code" VALUES(1,1,'2020-01-23 11:54:49.380905','token1',NULL,10000,NULL,'created');
INSERT INTO "claim_code" VALUES(2,1,'2020-01-23 11:55:33.789748','token2',NULL,10000,NULL,'created');
CREATE TABLE merchant_tx (
	id INTEGER NOT NULL, 
	date DATETIME, 
	user_id INTEGER NOT NULL, 
	wallet_address VARCHAR(255) NOT NULL, 
	amount INTEGER, 
	txid VARCHAR(255) NOT NULL, 
	direction BOOLEAN NOT NULL, 
	category VARCHAR(255) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	CHECK (direction IN (0, 1))
);
INSERT INTO "merchant_tx" VALUES(1,'2020-02-03 17:27:17.704739',1,'addr1',100,'txid1',1,'rebate');
INSERT INTO "merchant_tx" VALUES(2,'2020-02-03 17:28:53.819080',1,'addr1',100,'txid1',1,'rebate');
INSERT INTO "merchant_tx" VALUES(3,'2020-02-03 17:28:57.913607',1,'addr1',100,'txid1',1,'rebate');
CREATE TABLE settlement (
	id INTEGER NOT NULL, 
	date DATETIME, 
	user_id INTEGER NOT NULL, 
	token VARCHAR(255) NOT NULL, 
	bank_account VARCHAR(255) NOT NULL, 
	amount INTEGER NOT NULL, 
	settlement_address VARCHAR(255) NOT NULL, 
	amount_receive INTEGER NOT NULL, 
	txid VARCHAR(255), 
	status VARCHAR(255) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id), 
	UNIQUE (token)
);
INSERT INTO "settlement" VALUES(1,'2020-02-27 19:58:21.739256',1,'0959a6fa','114444777777722',100,'addr',95,'txid2','sent_zap');
CREATE TABLE bank (
	id INTEGER NOT NULL, 
	user_id INTEGER NOT NULL, 
	account_number VARCHAR(255) NOT NULL, 
	account_name VARCHAR(255) NOT NULL, 
	account_holder_address VARCHAR(255) NOT NULL, 
	bank_name VARCHAR(255) NOT NULL, 
	PRIMARY KEY (id), 
	FOREIGN KEY(user_id) REFERENCES user (id)
);
COMMIT;
