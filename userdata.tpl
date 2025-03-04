#!/bin/bash
set -e  # Exit immediately if any command fails
exec > /tmp/userdata.log 2>&1
echo "$(date) - Starting userdata script (Amazon Linux 2 with WordPress using RDS)"

# Ensure the SSM Agent is running
echo "$(date) - Ensuring SSM Agent is running..."
systemctl start amazon-ssm-agent
SYSTEMCTL_SSM_RESULT=$?
if [ $SYSTEMCTL_SSM_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to start SSM Agent. Exiting."
    exit 1
fi
systemctl enable amazon-ssm-agent
SYSTEMCTL_SSM_ENABLE_RESULT=$?
if [ $SYSTEMCTL_SSM_ENABLE_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to enable SSM Agent. Continuing, but this is concerning."
fi

echo "$(date) - SSM Agent started and enabled."

# Update package list
echo "$(date) - Updating package list..."
yum update -y
YUM_UPDATE_RESULT=$?
if [ $YUM_UPDATE_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: yum update failed.  Exiting."
    exit 1
fi

# **Upgrade PHP to 8.1**
echo "$(date) - Upgrading PHP to 8.1..."
amazon-linux-extras enable php8.1
PHP_EXTRAS_RESULT=$?
if [ $PHP_EXTRAS_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: amazon-linux-extras enable php8.1 failed. Exiting."
    exit 1
fi

yum clean metadata
YUM_CLEAN_RESULT=$?
if [ $YUM_CLEAN_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: yum clean metadata failed.  Continuing, but this is concerning."
fi

yum install -y php php-mysqlnd php-gd php-xml php-mbstring
YUM_PHP_INSTALL_RESULT=$?
if [ $YUM_PHP_INSTALL_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: yum install php php-mysqlnd php-gd php-xml php-mbstring failed. Exiting."
    exit 1
fi

echo "$(date) - PHP 8.1 installed."

# Verify PHP Version
echo "$(date) - Verifying PHP version..."
PHP_VERSION=$(php -v | head -n 1)
echo "$(date) - PHP Version: $PHP_VERSION"

# Exit if PHP Version does not contain "PHP 8.1"

if [[ ! "$PHP_VERSION" == *"PHP 8.1"* ]]; then
    echo "$(date) - ERROR: PHP version is not 8.1.  Exiting."
    exit 1
fi

# Install necessary tools
echo "$(date) - Installing necessary tools..."
yum install -y httpd wget unzip jq amazon-cloudwatch-agent -y
YUM_INSTALL_RESULT=$?
if [ $YUM_INSTALL_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: yum install failed.  Exiting."
    exit 1
fi

echo "$(date) - Packages updated and tools installed."

# Start and enable Apache
echo "$(date) - Starting and enabling Apache..."
systemctl start httpd
SYSTEMCTL_APACHE_START_RESULT=$?
if [ $SYSTEMCTL_APACHE_START_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to start Apache. Exiting."
    exit 1
fi

systemctl enable httpd
SYSTEMCTL_APACHE_ENABLE_RESULT=$?
if [ $SYSTEMCTL_APACHE_ENABLE_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to enable Apache. Continuing, but this is concerning."
fi

echo "$(date) - Apache started and enabled."

# Install wp-cli (WordPress command-line interface)
echo "$(date) - Installing wp-cli..."
cd /tmp
wget https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
WGET_WPCLI_RESULT=$?
if [ $WGET_WPCLI_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: wget wp-cli.phar failed.  Exiting."
    exit 1
fi
php wp-cli.phar --info
PHP_WPCLI_INFO_RESULT=$?
if [ $PHP_WPCLI_INFO_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: php wp-cli.phar --info failed.  This could indicate a broken PHP installation. Exiting."
    exit 1
fi
chmod +x wp-cli.phar
CHMOD_WPCLI_RESULT=$?
if [ $CHMOD_WPCLI_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: chmod +x wp-cli.phar failed.  Exiting."
    exit 1
fi
mv wp-cli.phar /usr/local/bin/wp
MV_WPCLI_RESULT=$?
if [ $MV_WPCLI_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: mv wp-cli.phar /usr/local/bin/wp failed.  Exiting."
    exit 1
fi
echo "$(date) - wp-cli installed."

# Download and extract WordPress
echo "$(date) - Downloading and extracting WordPress..."
wget https://wordpress.org/latest.tar.gz
WGET_WP_RESULT=$?
if [ $WGET_WP_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: wget latest.tar.gz failed. Exiting."
    exit 1
fi

tar xzf latest.tar.gz
TAR_EXTRACT_RESULT=$?
if [ $TAR_EXTRACT_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: tar xzf latest.tar.gz failed. Exiting."
    exit 1
fi

rm -rf /var/www/html/*
RM_WWW_RESULT=$?
if [ $RM_WWW_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: rm -rf /var/www/html/* failed. Exiting."
    exit 1
fi

cp -r wordpress/* /var/www/html/
CP_WWW_RESULT=$?
if [ $CP_WWW_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: cp -r wordpress/* /var/www/html/ failed. Exiting."
    exit 1
fi

chown -R apache:apache /var/www/html
CHOWN_WWW_RESULT=$?
if [ $CHOWN_WWW_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: chown -R apache:apache /var/www/html failed. Exiting."
    exit 1
fi

chmod -R 755 /var/www/html
CHMOD_WWW_RESULT=$?
if [ $CHMOD_WWW_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: chmod -R 755 /var/www/html failed. Exiting."
    exit 1
fi

echo "$(date) - WordPress downloaded and extracted."

# Create wp-config.php using wp-cli
echo "$(date) - Creating wp-config.php using wp-cli..."
cd /var/www/html

#  Set WP_HOME and WP_SITEURL before creating config
wp config set WP_HOME "https://${domain_name}" --raw --path='/var/www/html'
WP_CONFIG_SET_WP_HOME_RESULT=$?
wp config set WP_SITEURL "https://${domain_name}" --raw --path='/var/www/html'
WP_CONFIG_SET_WP_SITEURL_RESULT=$?

if [ $WP_CONFIG_SET_WP_HOME_RESULT -ne 0 ] || [ $WP_CONFIG_SET_WP_SITEURL_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to set WP_HOME or WP_SITEURL. Exiting."
    exit 1
fi

# Retrieve database credentials from Secrets Manager
echo "$(date) - Retrieving database credentials from Secrets Manager..."
DB_CREDS='${db_creds}'  # Terraform variable for database credentials JSON
DB_NAME=$(echo "$DB_CREDS" | jq -r '.dbname')
DB_USER=$(echo "$DB_CREDS" | jq -r '.username')
DB_PASSWORD=$(echo "$DB_CREDS" | jq -r '.password')
DB_HOST=$(echo "$DB_CREDS" | jq -r '.host')

if [ -z "$DB_NAME" ] || [ -z "$DB_USER" ] || [ -z "$DB_PASSWORD" ] || [ -z "$DB_HOST" ]; then
    echo "$(date) - ERROR: Failed to retrieve database credentials from Secrets Manager.  Check the DB_CREDS variable and the structure of the secret."
    exit 1
fi
echo "$(date) - Retrieved database credentials."

WP_CONFIG_CREATE_RESULT=0
wp config create \
    --dbname="$DB_NAME" \
    --dbuser="$DB_USER" \
    --dbpass="$DB_PASSWORD" \
    --dbhost="$DB_HOST" \
    --path='/var/www/html' \
    --force
WP_CONFIG_CREATE_RESULT=$?

if [ $WP_CONFIG_CREATE_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: wp config create failed. Check database credentials and host. Exiting."
    exit 1
fi

echo "$(date) - wp-config.php created."

# Add the HTTPS detection code to wp-config.php
echo "$(date) - Adding HTTPS detection code to wp-config.php"
CONFIG_FILE="/var/www/html/wp-config.php"
if ! grep -q "HTTP_X_FORWARDED_PROTO" "$CONFIG_FILE"; then
  sed -i "s/\/\* That's all, stop editing! Happy blogging. \*\//$(cat <<EOF
/**
 * Force SSL detection when behind a proxy or load balancer.
 */
if ( isset( \$_SERVER['HTTP_X_FORWARDED_PROTO'] ) && \$_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https' ) {
    \$_SERVER['HTTPS'] = 'on';
}

/**
 * Force SSL admin
 */
define('FORCE_SSL_ADMIN', true);
EOF
)\n\/\* That's all, stop editing! Happy blogging. \*\//" "$CONFIG_FILE"
  SED_CONFIG_RESULT=$?
  if [ $SED_CONFIG_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to add HTTPS detection code to wp-config.php. Exiting."
    exit 1
  fi
else
    echo "$(date) - HTTPS detection code already present in wp-config.php"
fi

# Generate salts and add them to wp-config.php
echo "$(date) - Generating salts and adding them to wp-config.php..."

wp config set AUTH_KEY "$(wp config get AUTH_KEY --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_AUTH_KEY_RESULT=$?
wp config set SECURE_AUTH_KEY "$(wp config get SECURE_AUTH_KEY --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_SECURE_AUTH_KEY_RESULT=$?
wp config set LOGGED_IN_KEY "$(wp config get LOGGED_IN_KEY --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_LOGGED_IN_KEY_RESULT=$?
wp config set NONCE_KEY "$(wp config get NONCE_KEY --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_NONCE_KEY_RESULT=$?
wp config set AUTH_SALT "$(wp config get AUTH_SALT --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_AUTH_SALT_RESULT=$?
wp config set SECURE_AUTH_SALT "$(wp config get SECURE_AUTH_SALT --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_SECURE_AUTH_SALT_RESULT=$?
wp config set LOGGED_IN_SALT "$(wp config get LOGGED_IN_SALT --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_LOGGED_IN_SALT_RESULT=$?
wp config set NONCE_SALT "$(wp config get NONCE_SALT --raw)" --raw --path='/var/www/html'
WP_CONFIG_SET_NONCE_SALT_RESULT=$?

if [ $WP_CONFIG_SET_AUTH_KEY_RESULT -ne 0 ] || [ $WP_CONFIG_SET_SECURE_AUTH_KEY_RESULT -ne 0 ] || [ $WP_CONFIG_SET_LOGGED_IN_KEY_RESULT -ne 0 ] || [ $WP_CONFIG_SET_NONCE_KEY_RESULT -ne 0 ] || [ $WP_CONFIG_SET_AUTH_SALT_RESULT -ne 0 ] || [ $WP_CONFIG_SET_SECURE_AUTH_SALT_RESULT -ne 0 ] || [ $WP_CONFIG_SET_LOGGED_IN_SALT_RESULT -ne 0 ] || [ $WP_CONFIG_SET_NONCE_SALT_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: One or more wp config set commands failed.  Exiting."
    exit 1
fi

echo "$(date) - Salts generated and added to wp-config.php."

# Test Database Connection
echo "$(date) - Testing Database Connection..."
wp db check --path='/var/www/html'
DB_CHECK_RESULT=$?
if [ $DB_CHECK_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Database connection failed. Check database credentials and host.  Exiting."
    exit 1
fi
echo "$(date) - Database connection successful."

# Install WordPress (Automated Install)
echo "$(date) - Installing WordPress..."

# Get WordPress admin credentials from JSON
echo "$(date) - Retrieving WordPress admin credentials from Secrets Manager..."
WP_ADMIN_CREDS='${wp_admin_creds}'
WP_ADMIN_USER=$(echo "$WP_ADMIN_CREDS" | jq -r '.username')
WP_ADMIN_PASSWORD=$(echo "$WP_ADMIN_CREDS" | jq -r '.password')
WP_ADMIN_EMAIL=$(echo "$WP_ADMIN_CREDS" | jq -r '.email')
echo "$(date) - Retrieved admin credentials: user=$WP_ADMIN_USER, email=$WP_ADMIN_EMAIL"

wp core install \
    --path='/var/www/html' \
    --url="https://${domain_name}" \
    --title='WordPress Site' \
    --admin_user="$WP_ADMIN_USER" \
    --admin_password="$WP_ADMIN_PASSWORD" \
    --admin_email="$WP_ADMIN_EMAIL"
WP_INSTALL_RESULT=$?
if [ $WP_INSTALL_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: WordPress installation failed. Exiting."
    exit 1
fi
echo "$(date) - WordPress installed successfully."

# Configure Apache with proper Virtual Host
echo "$(date) - Configuring Apache..."

# Use 'cat' to read the external vhost.conf.tpl file
cat ./vhost.conf.tpl > /etc/httpd/conf.d/wordpress.conf

VHOST_CONFIG_RESULT=$?
if [ $VHOST_CONFIG_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to write Apache VirtualHost config. Exiting."
    exit 1
fi
echo "$(date) - Apache VirtualHost configured."

# Create .htaccess file
echo "$(date) - Creating .htaccess file..."
# Use 'cat' to read the external htaccess.tpl file.  MUCH cleaner.
cat ./htaccess.tpl > /var/www/html/.htaccess
HTACCESS_CONTENT_RESULT=$?
if [ $HTACCESS_CONTENT_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to write .htaccess file. Exiting."
    exit 1
fi
echo "$(date) - .htaccess file created."

# Set proper permissions
echo "$(date) - Setting file permissions..."
chown apache:apache /var/www/html/.htaccess
CHOWN_HTACCESS_RESULT=$?
if [ $CHOWN_HTACCESS_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: chown apache:apache /var/www/html/.htaccess failed. Exiting."
    exit 1
fi
chmod 644 /var/www/html/.htaccess
CHMOD_HTACCESS_RESULT=$?
if [ $CHMOD_HTACCESS_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: chmod 644 /var/www/html/.htaccess failed. Exiting."
    exit 1
fi
echo "$(date) - File permissions set."

# Configure SELinux
echo "$(date) - Configuring SELinux..."
setsebool -P httpd_can_network_connect_db 1
SETSEBOOL_DB_RESULT=$?
if [ $SETSEBOOL_DB_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: setsebool -P httpd_can_network_connect_db 1 failed. Check SELinux configuration. Exiting."
    exit 1
fi
setsebool -P httpd_can_network_connect 1
SETSEBOOL_NETWORK_RESULT=$?
if [ $SETSEBOOL_NETWORK_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: setsebool -P httpd_can_network_connect 1 failed. Check SELinux configuration. Exiting."
    exit 1
fi

semanage fcontext -a -t httpd_sys_content_t "/var/www/html(/.*)?"
SEMANAGE_CONTENT_RESULT=$?
if [ $SEMANAGE_CONTENT_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: semanage fcontext -a -t httpd_sys_content_t failed.  Check that semanage is installed correctly. Exiting."
    exit 1
fi
semanage fcontext -a -t httpd_sys_rw_content_t "/var/www/html/wp-content(/.*)?"
SEMANAGE_RW_RESULT=$?
if [ $SEMANAGE_RW_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: semanage fcontext -a -t httpd_sys_rw_content_t failed. Check that semanage is installed correctly. Exiting."
    exit 1
fi
restorecon -Rv /var/www/html
RESTORECON_RESULT=$?
if [ $RESTORECON_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: restorecon -Rv /var/www/html failed. Check SELinux configuration. Exiting."
    exit 1
fi
echo "$(date) - SELinux configured."

# Enable mod_rewrite
echo "$(date) - Enabling mod_rewrite..."
sed -i 's/#LoadModule rewrite_module modules\/mod_rewrite.so/LoadModule rewrite_module modules\/mod_rewrite.so/' /etc/httpd/conf.modules.d/00-base.conf
SED_MODREWRITE_RESULT=$?
if [ $SED_MODREWRITE_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: sed to enable mod_rewrite failed. Exiting."
    exit 1
fi
echo "$(date) - mod_rewrite enabled."

# Restart Apache
echo "$(date) - Restarting Apache..."
systemctl restart httpd
SYSTEMCTL_RESTART_APACHE_RESULT=$?
if [ $SYSTEMCTL_RESTART_APACHE_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Failed to restart Apache. Exiting."
    exit 1
fi

echo "$(date) - Apache restarted."

# Search and replace database URLs
echo "$(date) - Searching and replacing database URLs to enforce HTTPS..."
wp search-replace 'http://${domain_name}' 'https://${domain_name}' --skip-columns=guid --all-tables --path='/var/www/html' --quiet --url="https://${domain_name}"
DB_REPLACE_RESULT=$?
if [ $DB_REPLACE_RESULT -ne 0 ]; then
    echo "$(date) - ERROR: Database search and replace failed.  Exiting."
    exit 1
fi
echo "$(date) - Database URLs updated to HTTPS."

echo "$(date) - Userdata script completed successfully."