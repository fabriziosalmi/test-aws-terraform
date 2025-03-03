# vhost.conf.tpl
<VirtualHost *:80>
    ServerName ${domain_name}
    Redirect permanent / https://${domain_name}/
</VirtualHost>

<VirtualHost *:443>
    ServerName ${domain_name}
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog /var/log/httpd/error.log
    CustomLog /var/log/httpd/access.log combined

    SSLEngine on
    SSLCertificateFile /etc/pki/tls/certs/localhost.crt
    SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
</VirtualHost>