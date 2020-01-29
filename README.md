# nextcloud

Installs and configures a nextcloud instance

## Requirements

A Debian-based system

## Role Variables

| Name                            | Required/Default          | Description                                                                                                                     |
|:--------------------------------|:--------------------------|:--------------------------------------------------------------------------------------------------------------------------------|
| `global_cache_dir`              | :heavy_check_mark:        | Cache directory to download Nextcloud files to on the execution machine running this playbook.                                  |
| `nextcloud_version`             | `13.0.0`                  | Version number of the Nextcloud version to be installed                                                                         |
| `nextcloud_system_user`         | `www-data`                | User under which Nextcloud should run. The user has to exist.                                                                   |
| `nextcloud_system_group`        | `www-data`                | Group under which Nextcloud should run. The group has to exist.                                                                 |
| `nextcloud_path`                | `/var/www/nextcloud`      | Path to install nextcloud to                                                                                                    |
| `nextcloud_path_old`            | `/var/www/nextcloud_old`  | Path to store the nextcloud dir when upgrading. Note that `nextcloud_version` number will be added to that path.                |
| `nextcloud_data_dir_path`       | `/var/www/nextcloud_data` | Path to store the nextcloud data in. This can not be in the `{{ nextcloud_path }}` itself, because we move dirs during upgrades |
| `nextcloud_mysql_user`          | `nextcloud`               | Default user to use for database connections                                                                                    |
| `nextcloud_mysql_password`      | :heavy_check_mark:        | Mysql password                                                                                                                  |
| `nextcloud_mysql_database_name` | `nextcloud`               | Default database name                                                                                                           |
| `nextcloud_user`                | `admin`                   | Admin user to be installed                                                                                                      |
| `nextcloud_password`            | :heavy_check_mark:        | Admin password                                                                                                                  |
| `nextcloud_plugins`             | `[]`                      | List of Nextcloud plugins to install and activate                                                                               |
| `nextcloud_config`              | `[]`                      | Dict of Nextcloud setting read more below                                                                                       |
| `nextcloud_ldap_enable`         | `false`                   | Enable ldap                                                                                                                     |
| `nextcloud_ldap`                | `false`                   | Dict containing the ldap attributes                                                                                             |
| `nextcloud_admins`              | `false`                   | Dict containing the ldap usernames as key that should be added to the admin group                                               |

### LDAP Settings
This is a list of the ldap attributes, for a description and behaviour please see the [Nextcloud documentation](https://docs.nextcloud.com/server/13/admin_manual/configuration_user/user_auth_ldap.html#configuration)
To set a LDAP attribute put the attribute in the nextcloud_ldap dict.
```yml
nextcloud_ldap:
  ldapHost: ldaps://ldap.example.com
```

| Name                            |
|:--------------------------------|
| `hasMemberOfFilterSupport`      |
| `hasPagedResultSupport`         |
| `homeFolderNamingRule`          |
| `lastJpegPhotoLookup`           |
| `ldapAgentName`                 |
| `ldapAgentPassword`             |
| `ldapAttributesForGroupSearch`  |
| `ldapAttributesForUserSearch`   |
| `ldapBackupHost`                |
| `ldapBackupPort`                |
| `ldapBase`                      |
| `ldapBaseGroups`                |
| `ldapBaseUsers`                 |
| `ldapCacheTTL`                  |
| `ldapConfigurationActive`       |
| `ldapDefaultPPolicyDN`          |
| `ldapDynamicGroupMemberURL`     |
| `ldapEmailAttribute`            |
| `ldapExperiencedAdmin`          |
| `ldapExpertUUIDGroupAttr`       |
| `ldapExpertUUIDUserAttr`        |
| `ldapExpertUsernameAttr`        |
| `ldapGidNumber`                 |
| `ldapGroupDisplayName`          |
| `ldapGroupFilter`               |
| `ldapGroupFilterGroups`         |
| `ldapGroupFilterMode`           |
| `ldapGroupFilterObjectclass`    |
| `ldapGroupMemberAssocAttr`      |
| `ldapHost`                      |
| `ldapIgnoreNamingRules`         |
| `ldapLoginFilter`               |
| `ldapLoginFilterAttributes`     |
| `ldapLoginFilterEmail`          |
| `ldapLoginFilterMode`           |
| `ldapLoginFilterUsername`       |
| `ldapNestedGroups`              |
| `ldapOverrideMainServer`        |
| `ldapPagingSize`                |
| `ldapPort`                      |
| `ldapQuotaAttribute`            |
| `ldapQuotaDefault`              |
| `ldapTLS`                       |
| `ldapUserDisplayName`           |
| `ldapUserDisplayName2`          |
| `ldapUserFilter`                |
| `ldapUserFilterGroups`          |
| `ldapUserFilterMode`            |
| `ldapUserFilterObjectclass`     |
| `ldapUuidGroupAttribute`        |
| `ldapUuidUserAttribute`         |
| `turnOffCertCheck`              |
| `turnOnPasswordChange`          |
| `useMemberOfToDetectMembership` |


### `nextcloud_config`
`nextcloud_config` is an object containing the settings for the Nextcloud instance. Do not use it to enable/disable apps and/or for setting up ldap.
The setup of this object is similar to the output of the `php occ config:list` option.
Under `nextcloud_config` you should have two objects called `system` and `apps` under those objects you can further describe the configuration as an example setting the trusted domains for Nextcloud.
```yml
nextcloud_config:
  system:
    trusted_domains:
      - nc.example.com
      - nextcloud.example.com
```
Every object that you put under nextcloud config is expanded in its path and then written to the Nextcloud instance.

## Example Playbook

```yml
global_cache_dir: "{{ lookup('env', 'HOME') }}/.cache/stuvus"
nextcloud_mysql_password: mysqlpassword
nextcloud_password: password
nextcloud_version: 13.0.0
nextcloud_plugins:
  - mail
nextcloud_config:
  system:
    passwordsalt: salthere
    debug: false
    secret: mysecret
    trusted_domains:
      - nextcloud02.stuvus.uni-stuttgart.de
    trusted_proxies:
      - 129.69.139.23
    overwrite.cli.url: http://localhost
    dbtype: mysql
    dbname: nextcloud
    dbport: ''
    dbtableprefix: oc_
    dbuser: nextcloud
    dbpassword: fuckingchangethis
    memcache.local: "\\OC\\Memcache\\Redis"
    memcache.locking: "\\OC\\Memcache\\Redis"
    redis:
      host: localhost
      port: 6379
    logtimezone: UTC
    installed: true
    loglevel: 2
  apps:
    DefaultGroup:
      default_groups: "[\"calendar_default\"]"
nextcloud_ldapAgentName: agent_dn
nextcloud_ldapAgentPassword: agent_password
nextcloud_ldapBase: dc=ldapbase,dc=de
nextcloud_ldapBaseUsers: dc=users,dc=ldapbase,dc=de
nextcloud_ldapBaseGroups: dc=users,dc=ldapbase,dc=de
nextcloud_ldapGroupFilter: "(&(|(objectclass=posixGroup)))"
nextcloud_ldapGroupFilterObjectclass: posixGroup
nextcloud_ldapGroupMemberAssocAttr: memberUid
nextcloud_ldapHost: ldaps://url.org.de
nextcloud_ldapLoginFilter: "(&(|(objectclass=posixAccount))(uid=%uid))"
nextcloud_ldapUserDisplayName: cn
nextcloud_ldapUserFilter: "(|(objectclass=gosaAccount)(objectclass=inetOrgPerson)(objectclass=posixAccount))"
nextcloud_ldapUserFilterObjectclass: gosaAccount;inetOrgPerson;posixAccount
nextcloud_ldaphasMemberOfFilterSupport: " "
nextcloud_ldapPort: 636
nextcloud_ldapEmailAttribute: mail

served_domains:
  - domains:
      - nextcloud02
    privkey_path: /etc/ssl/privkey.pem  # privkey.pem will placed there>
    fullchain_path: /etc/ssl/fullchain.pem # fullchain.pem will placed there>
    crypto: true
    allowed_ip_ranges:
      - 129.69.139.0/25
    https: true
    headers:
      - X-Content-Type-Options nosniff
      - X-Frame-Options "SAMEORIGIN"
      - X-XSS-Protection "1; mode=block"
      - X-Robots-Tag none
      - X-Download-Options noopen
      - X-Permitted-Cross-Domain-Policies none
    default_server: true
    root: /var/www/nextcloud
    client_max_body_size: 2048M
    fastcgi_buffers: 64 4K;
    index_files:
      - index.php
    locations:
      - condition: /robots.txt
        content:
        |
          allow all;
          log_not_found off;
          access_log off;
      - condition: /.well-known/carddav
        content:
        |
         return 301 $scheme://$host/remote.php/dav;
      - condition: /.well-known/caldav
        content:
        |
         return 301 $scheme://$host/remote.php/dav;
      - condition: /
        content:
        |
         rewrite ^ /index.php$uri;
      - condition: ~ ^/(?:build|tests|config|lib|3rdparty|templates|data)/
        ignore_access: True
        content:
        |
         deny all;
      - condition: ~ ^/(?:\.|autotest|occ|issue|indie|db_|console)
        ignore_access: True
        content:
        |
         deny all;
      - condition:  ~ ^/(?:index|remote|public|cron|core/ajax/update|status|ocs/v[12]|updater/.+|ocs-provider/.+|core/templates/40[34])\.php(?:$|/)
        content:
        |
          fastcgi_split_path_info ^(.+\.php)(/.*)$;
          include fastcgi_params;
          fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
          fastcgi_param PATH_INFO $fastcgi_path_info;
          fastcgi_param HTTPS on;
          #Avoid sending the security headers twice
          fastcgi_param modHeadersAvailable true;
          fastcgi_param front_controller_active true;
          fastcgi_pass php-handler;
          fastcgi_intercept_errors on;
          fastcgi_request_buffering off;
      - condition: ~ ^/(?:updater|ocs-provider)(?:$|/)
        content:
        |
          try_files $uri/ =404;
          index index.php;
      - condition: ~* \.(?:css|js|woff|svg|gif)
        content:
        |
          try_files $uri /index.php$uri$is_args$args;
          add_header Cache-Control "public, max-age=7200";
          add_header X-Content-Type-Options nosniff;
          add_header X-Frame-Options "SAMEORIGIN";
          add_header X-XSS-Protection "1; mode=block";
          add_header X-Robots-Tag none;
          add_header X-Download-Options noopen;
          add_header X-Permitted-Cross-Domain-Policies none;
          access_log off;
      - condition: ~* \.(?:png|html|ttf|ico|jpg|jpeg)
        content:
        |
          try_files $uri /index.php$uri$is_args$args;
          access_log off;

mariadb_binlog_format: row
nginx:
  gzip: off
nginx_upstreams:
  - name: php-handler
    path:  unix:/run/php/nextcloud-fpm.sock

php_fpm_pools:
  - name: fpm-host
    listen: /run/php/nextcloud-fpm.sock
    user: www-data
    pm: static
    pm_max_children: 20
    pm_start_servers: 20
    processes_priority: -19
    envs:
      HOSTNAME: "$HOSTNAME"
      PATH: "/usr/local/bin:/usr/bin:/bin"
      TMP: /tmp
      TMPDIR: /tmp
      TEMP: /tmp
php_fpm_php_ini_values:
  - section: APC
    option: apc.enabled
    value: 1
  - section: PHP
    option: opcache.enable
    value: 1
  - section: PHP
    option: opcache.enable_cli
    value: 1
  - section: PHP
    option: opcache.interned_strings_buffer
    value: 8
  - section: PHP
    option: opcache.memory_consumption
    value: 128
  - section: PHP
    option: opcache.save_comments
    value: 1
  - section: PHP
    option: opcache.revalidate_freq
    value: 1
```

## License

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).


## Author Information

- [Fritz Otlinghaus (Scriptkiddi)](https://github.com/scriptkiddi) _fritz.otlinghaus@stuvus.uni-stuttgart.de_
