<VirtualHost *:80>
    ServerAdmin fabrizio.salmi@gmail.com
    DocumentRoot /var/www/html
    ErrorLog /var/log/httpd/wordpress-error.log
    CustomLog /var/log/httpd/wordpress-access.log combined

    <Directory /var/www/html>
        Options FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>