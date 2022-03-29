use `spring-oauth`;
create table persistent_logins (
       username varchar(64) not null,
       series varchar(64) primary key,
       token varchar(64) not null,
       last_used timestamp not null
);

CREATE TABLE oauth2_authorized_client (
      client_registration_id varchar(100) NOT NULL,
      principal_name varchar(200) NOT NULL,
      access_token_type varchar(100) NOT NULL,
      access_token_value varchar(5000) NOT NULL,
      access_token_issued_at timestamp NOT NULL,
      access_token_expires_at timestamp NOT NULL,
      access_token_scopes varchar(1000) DEFAULT NULL,
      refresh_token_value varchar(5000) DEFAULT NULL,
      refresh_token_issued_at timestamp DEFAULT NULL,
      created_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
      PRIMARY KEY (client_registration_id, principal_name)
);


CREATE TABLE oauth2_registered_client (
      id varchar(100) NOT NULL,
      client_id varchar(100) NOT NULL,
      client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
      client_secret varchar(200) DEFAULT NULL,
      client_secret_expires_at timestamp DEFAULT NULL,
      client_name varchar(200) NOT NULL,
      client_authentication_methods varchar(1000) NOT NULL,
      authorization_grant_types varchar(1000) NOT NULL,
      redirect_uris varchar(1000) DEFAULT NULL,
      scopes varchar(1000) NOT NULL,
      client_settings varchar(2000) NOT NULL,
      token_settings varchar(2000) NOT NULL,
      PRIMARY KEY (id)
);

CREATE TABLE oauth2_authorization_consent (
      registered_client_id varchar(100) NOT NULL,
      principal_name varchar(200) NOT NULL,
      authorities varchar(1000) NOT NULL,
      PRIMARY KEY (registered_client_id, principal_name)
);

CREATE TABLE oauth2_authorization (
      id varchar(100) NOT NULL,
      registered_client_id varchar(100) NOT NULL,
      principal_name varchar(200) NOT NULL,
      authorization_grant_type varchar(100) NOT NULL,
      attributes text DEFAULT NULL,
      state varchar(500) DEFAULT NULL,
      authorization_code_value blob DEFAULT NULL,
      authorization_code_issued_at timestamp DEFAULT NULL,
      authorization_code_expires_at timestamp DEFAULT NULL,
      authorization_code_metadata varchar(1000) DEFAULT NULL,
      access_token_value varchar(1000) DEFAULT NULL,
      access_token_issued_at timestamp DEFAULT NULL,
      access_token_expires_at timestamp DEFAULT NULL,
      access_token_metadata varchar(1000) DEFAULT NULL,
      access_token_type varchar(100) DEFAULT NULL,
      access_token_scopes varchar(1000) DEFAULT NULL,
      oidc_id_token_value varchar(1000) DEFAULT NULL,
      oidc_id_token_issued_at timestamp DEFAULT NULL,
      oidc_id_token_expires_at timestamp DEFAULT NULL,
      oidc_id_token_metadata varchar(1000) DEFAULT NULL,
      refresh_token_value varchar(1000) DEFAULT NULL,
      refresh_token_issued_at timestamp DEFAULT NULL,
      refresh_token_expires_at timestamp DEFAULT NULL,
      refresh_token_metadata varchar(1000) DEFAULT NULL,
      PRIMARY KEY (id)
);


create table users(
      `username` varchar(200) not null primary key,
      `password` varchar(500) not null,
      enabled boolean not null
);
create table authorities (
     username varchar(200) not null,
     authority varchar(500) not null
);
create unique index ix_auth_username on authorities (username,authority);