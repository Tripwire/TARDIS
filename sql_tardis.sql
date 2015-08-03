CREATE DATABASE TARDIS;

use TARDIS;

CREATE TABLE attackInventory(
   attack_id INT NOT NULL AUTO_INCREMENT,
   attacker_ip INT(11) UNSIGNED,
   attacker_host VARCHAR(255),
   attacker_user VARCHAR(255),
   victim_ip INT(11) UNSIGNED,
   victim_host VARCHAR(255),
   attack_time VARCHAR(255) NOT NULL,
   attack_log VARCHAR(2048) NOT NULL,
   threat_id VARCHAR(255) NOT NULL,
   PRIMARY KEY ( attack_id )
   );

CREATE TABLE assetVulnerabilities(
   victim_ip INT(11) NOT NULL ,
   threat_id VARCHAR(255) NOT NULL,
   active VARCHAR(255) NOT NULL,
   PRIMARY KEY ( victim_ip, threat_id )
   );
