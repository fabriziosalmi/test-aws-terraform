# Terraform WordPress Deployment on AWS

This Terraform project deploys a highly available WordPress website on AWS. It includes the following components:

*   **Virtual Private Cloud (VPC):** A dedicated network for the WordPress deployment.
*   **Subnets:** Public and private subnets for different tiers of the application.
*   **Internet Gateway:** Enables communication with the internet.
*   **Route Tables:** Defines network routes within the VPC.
*   **Security Groups:** Controls inbound and outbound traffic to resources.  Includes a dedicated security group for EC2 instances allowing HTTP traffic from the Application Load Balancer (ALB).
*   **Database Subnet Group:** Specifies subnets for the RDS database instance.
*   **Secrets Manager:** Securely stores the database password and WordPress administrator credentials.
*   **RDS MySQL Database:** A managed database instance for WordPress.
*   **Application Load Balancer (ALB):** Distributes traffic across multiple EC2 instances.
*   **WAFv2 Web ACL:** Protects the application from common web exploits.
*   **Target Group:** Defines the set of EC2 instances behind the ALB.  Configured with health checks to ensure instance availability.
*   **Listeners:** Configures the ALB to listen on HTTP (redirects to HTTPS) and HTTPS ports.
*   **Route53 Records:** Creates DNS records for the WordPress site, pointing to the ALB.
*   **ACM Certificate:** Provides SSL/TLS encryption for secure communication.
*   **Launch Template:** Defines the configuration for EC2 instances, including the AMI, instance type, security groups, and user data.
*   **Auto Scaling Group (ASG):** Automatically scales the number of EC2 instances based on traffic.
*   **IAM Roles and Instance Profiles:** Provides necessary permissions to EC2 instances.
*   **CloudWatch Logs:** Collects logs for monitoring.
*   **CloudFront Distribution:** Content Delivery Network (CDN) for improved performance (optional, but included).

## Prerequisites

*   [Terraform](https://www.terraform.io/downloads.html) installed.
*   [AWS CLI](https://aws.amazon.com/cli/) installed and configured with appropriate credentials.
*   An AWS account.
*   A registered domain name (e.g., `test.example.com`) managed by Route 53. You'll need the Route 53 zone ID for your domain.

## Getting Started

1.  **Clone the repository:**

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2.  **Configure the AWS CLI:**

    Ensure you have the AWS CLI configured with the necessary credentials and default region:

    ```bash
    aws configure
    ```

3.  **Initialize Terraform:**

    ```bash
    terraform init
    ```

4.  **Set Variables:**

    Modify the `variables.tf` file or create a `terraform.tfvars` file to customize the deployment. Key variables include:

    *   `aws_region`: The AWS region to deploy to (e.g., "us-east-1"). **Important:** Ensure that all resources (AMI, key pair, etc.) are available in this region.
    *   `ami_id`: The AMI ID to use for the EC2 instances. The default is set to an Amazon Linux 2 AMI, but **you *must* verify this AMI ID is valid in the region you are deploying to. AMI IDs are region-specific!**  Find appropriate AMI in the AWS Marketplace or using the AWS CLI/Console.
    *   `instance_type`: The EC2 instance type (e.g., "t3.micro").  Consider `t3.medium` or larger for production workloads.
    *   `key_name`: The name of your AWS key pair for SSH access (optional).  If you omit this, you will not be able to SSH into the instances.  Consider using AWS Systems Manager Session Manager instead of SSH for better security.
    *   `db_name`: The name of the MySQL database.
    *   `db_user`: The username for the MySQL database.
    *   `desired_capacity`, `max_size`, `min_size`: The desired, maximum, and minimum number of EC2 instances in the Auto Scaling Group.  Adjust these based on your expected traffic.  `desired_capacity` should be between `min_size` and `max_size`.
    *   `db_instance_type`: The database instance type (e.g., "db.t3.small").  Choose a larger instance type for production databases (e.g., `db.m5.large`).
    *   `domain_name`: The full subdomain for your WordPress site (e.g., "wordpress.example.com"). This *must* match a valid domain name configured in Route 53.  Ensure the domain is properly delegated to AWS Name Servers.
    *   `wp_admin_email`: The email address for the WordPress administrator account. This will be used to create the WordPress admin user.
    *   `allowed_inbound_cidr_blocks`: A list of CIDR blocks allowed to access the ALB (HTTP/HTTPS). **Defaults to `0.0.0.0/0` (all IPs), which is highly insecure for production.  Restrict this to your specific IP addresses or CIDR blocks.**
    *   `db_allocated_storage`: The amount of storage allocated to the RDS instance in GB.
    *   `db_skip_final_snapshot`:  Whether to skip the final snapshot when destroying the database.  **Set this to `false` for production to ensure a backup is created before deletion.**
    *   `db_backup_retention_period`:  The number of days to retain automated backups for the RDS instance.
    *   `db_performance_insights_enabled`: Whether to enable Performance Insights for the RDS instance.  Recommended for monitoring database performance.
    *   `db_performance_insights_retention_period`: The retention period (in days) for Performance Insights data.
    *   `db_monitoring_interval`:  The interval (in seconds) for RDS Enhanced Monitoring. Valid values: 0 (disabled), 10, 30, or 60.

    Example `terraform.tfvars`:

    ```terraform
    aws_region       = "eu-west-1"
    ami_id           = "ami-xxxxxxxxxxxxxxxxx"  # Replace with a valid AMI ID for your region!
    key_name         = "my-key-pair"        # Replace with your key pair name
    domain_name      = "wordpress.example.com"
    db_name          = "wordpressdb"
    db_user          = "wordpressuser"
    db_instance_type = "db.t3.micro"
    wp_admin_email   = "admin@example.com" # Replace with the wordpress admin email
    allowed_inbound_cidr_blocks = ["192.0.2.0/24", "203.0.113.0/24"] # Replace with your allowed IPs
    db_skip_final_snapshot = false # Set to false for production to ensure a backup is created
    db_performance_insights_enabled = true
    db_monitoring_interval = 60
    ```

5.  **Review the Plan:**

    ```bash
    terraform plan
    ```

6.  **Apply the Configuration:**

    ```bash
    terraform apply
    ```

    Type `yes` to approve the changes.

7.  **Complete WordPress Installation:**

    *   Once the EC2 instances are running, access your WordPress site using the URL provided in the Terraform outputs.
    *   The WordPress installation will be automated using the credentials stored in AWS Secrets Manager, but you may still need to configure plugins or themes.  The administrator username, password, and email are stored securely and retrieved by the EC2 instances during provisioning.

## Important Files

*   `main.tf`: The main Terraform configuration file containing the resource definitions.  See the "Understanding the Terraform Code" section below for a detailed breakdown.
*   `variables.tf`: Defines the input variables for the project, allowing for customization of the deployment.  See the "Setting Variables" section above.
*   `outputs.tf`: Defines the output values that will be displayed after the deployment, providing important information such as the ALB URL and database endpoint.
*   `userdata.tpl`: A template file used to configure the EC2 instances on launch, including installing WordPress and configuring the database connection.  **Check `/tmp/userdata.log` on the EC2 instance for any errors during setup.** This script uses `wp-cli` to automate the WordPress installation.
*   `README.md`: This file.

## Understanding the Terraform Code (`main.tf`)

This section provides a detailed explanation of the resources defined in `main.tf`.

*   **`random_string`:** Generates a random string to ensure unique resource names, preventing naming conflicts.  This is especially important when deploying multiple instances of the same infrastructure.

    ```terraform
    resource "random_string" "random" {
      length  = 8
      special = false
      upper   = false
    }
    ```

*   **`locals`:** Defines local variables used throughout the configuration.  Currently, it defines the CIDR block for the VPC.

    ```terraform
    locals {
      cidr_block = "10.0.0.0/16"
    }
    ```

    *   **Customization:**  The `cidr_block` can be changed to fit your network requirements.  Ensure that it does not conflict with any existing networks.

*   **`aws_vpc`:** Creates the Virtual Private Cloud (VPC), a logically isolated section of the AWS cloud.

    ```terraform
    resource "aws_vpc" "main" {
      cidr_block = local.cidr_block

      tags = {
        Name = "wordpress-vpc-${random_string.random.result}"
      }
    }
    ```

    *   **Customization:** You can adjust the `cidr_block` and add more tags for organization.

*   **`aws_subnet` (Public and Private):** Creates the subnets within the VPC.  Public subnets have a direct route to the internet, while private subnets do not.

    ```terraform
    resource "aws_subnet" "public_subnet_a" {
      vpc_id            = aws_vpc.main.id
      cidr_block        = cidrsubnet(local.cidr_block, 8, 1)
      availability_zone = "${var.aws_region}a"
      map_public_ip_on_launch = true

      tags = {
        Name = "public-subnet-a-${random_string.random.result}"
      }
    }
    ```

    *   **Customization:**  You can adjust the `cidr_block`, `availability_zone`, and `map_public_ip_on_launch` settings.  The `cidrsubnet` function is used to divide the VPC's CIDR block into smaller subnets. `map_public_ip_on_launch` is true for Public subnets, enabling EC2 instances to receive a public IP. Note the numbering used for the cidrsubnet function and ensure that the private and public subnets do not overlap.
    *   **Important:**  The availability zones should correspond to the chosen AWS region.

*   **`aws_internet_gateway`:** Creates an Internet Gateway (IGW), allowing communication between the VPC and the internet.

    ```terraform
    resource "aws_internet_gateway" "gw" {
      vpc_id = aws_vpc.main.id

      tags = {
        Name = "wordpress-igw-${random_string.random.result}"
      }
    }
    ```

*   **`aws_route_table` (Public):** Creates a route table for the public subnets, routing all traffic to the Internet Gateway.

    ```terraform
    resource "aws_route_table" "public_route_table" {
      vpc_id = aws_vpc.main.id

      route {
        cidr_block = "0.0.0.0/0"
        gateway_id = aws_internet_gateway.gw.id
      }

      tags = {
        Name = "public-route-table-${random_string.random.result}"
      }
    }
    ```

*   **`aws_route_table_association`:** Associates the public subnets with the public route table.

    ```terraform
    resource "aws_route_table_association" "public_subnet_a" {
      subnet_id      = aws_subnet.public_subnet_a.id
      route_table_id = aws_route_table.public_route_table.id
    }
    ```

*   **`aws_security_group`:** Creates security groups to control inbound and outbound traffic to the resources.  Three security groups are defined: `ec2_sg`, `allow_http_https`, and `allow_mysql`.

    ```terraform
    resource "aws_security_group" "ec2_sg" {
      name        = "ec2-wordpress-sg-${random_string.random.result}"
      description = "Allow HTTP traffic from the ALB"
      vpc_id      = aws_vpc.main.id

      ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        security_groups = [aws_security_group.allow_http_https.id]  # <--- ALLOW FROM THE ALB SG
        description = "Allow HTTP traffic from the ALB"
      }

      egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        description = "Allow all outbound traffic"
      }

      tags = {
        Name = "ec2-wordpress-sg-${random_string.random.result}"
      }
    }
    ```

    ```terraform
    resource "aws_security_group" "allow_http_https" {
      name        = "allow_http_https-${random_string.random.result}"
      description = "Allow HTTP and HTTPS traffic"
      vpc_id      = aws_vpc.main.id

      ingress {
        from_port   = 80
        to_port     = 80
        protocol    = "tcp"
        cidr_blocks = var.allowed_inbound_cidr_blocks  # Use a variable for allowed IPs.  Defaults to 0.0.0.0/0 in variables.tf
        description = "Allow HTTP traffic"
      }

      ingress {
        from_port   = 443
        to_port     = 443
        protocol    = "tcp"
        cidr_blocks = var.allowed_inbound_cidr_blocks # Use a variable for allowed IPs.  Defaults to 0.0.0.0/0 in variables.tf
        description = "Allow HTTPS traffic"
      }

      egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        description = "Allow all outbound traffic"
      }

      tags = {
        Name = "allow_http_https-${random_string.random.result}"
      }
    }
    ```

    ```terraform
    resource "aws_security_group" "allow_mysql" {
      name        = "allow_mysql-${random_string.random.result}"
      description = "Allow MySQL traffic from EC2 instances in the allow_http_https SG"
      vpc_id      = aws_vpc.main.id

      ingress {
        from_port   = 3306
        to_port     = 3306
        protocol    = "tcp"
        security_groups = [aws_security_group.allow_http_https.id]
        description = "Allow MySQL from app servers (allow_http_https SG)"
      }

      egress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
        description = "Allow all outbound traffic"
      }

      tags = {
        Name = "allow_mysql-${random_string.random.result}"
      }
    }
    ```

    *   **`ec2_sg`:**  Allows HTTP traffic from the ALB to the EC2 instances.  This is *crucial* for the application to function. The ingress rule specifies that traffic is allowed only from the `allow_http_https` security group.
    *   **`allow_http_https`:** Allows HTTP and HTTPS traffic from the internet (or specified CIDR blocks) to the ALB. **The `allowed_inbound_cidr_blocks` variable *must* be restricted for production environments.** The egress rule allows all outbound traffic.
    *   **`allow_mysql`:** Allows MySQL traffic from the EC2 instances (specifically, from the `allow_http_https` security group) to the RDS database.

    *   **Customization:**  Carefully review and adjust the security group rules to meet your specific security requirements.

*   **`aws_db_subnet_group`:** Creates a database subnet group, specifying the subnets where the RDS database instance will be created.

    ```terraform
    resource "aws_db_subnet_group" "db_subnet_group" {
      name       = "db-subnet-group-${random_string.random.result}"
      subnet_ids = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]

      tags = {
        Name = "DB Subnet Group-${random_string.random.result}"
      }
    }
    ```

*   **`aws_secretsmanager_secret`:** Creates a secret in AWS Secrets Manager to store the database password. This is a secure way to manage sensitive information.  Separate secrets are created for the database password and WordPress admin credentials.

    ```terraform
    resource "aws_secretsmanager_secret" "db_password" {
      name                    = "wp-db-pass-${random_string.random.result}"
      description            = "Password for the WordPress database"
      recovery_window_in_days = 7
    }
    ```
    ```terraform
    resource "aws_secretsmanager_secret" "wp_admin_creds" {
      name                    = "wp-admin-creds-${random_string.random.result}"
      description            = "WordPress admin credentials"
      recovery_window_in_days = 7
    }
    ```

    *  The `recovery_window_in_days` attribute specifies how many days Secrets Manager waits before permanently deleting a secret that has been marked for deletion.

*   **`random_password`:** Generates a random password for the database.

    ```terraform
    resource "random_password" "db_password" {
      length           = 16
      special          = true
      override_special = "!#$%&*()-_=+[]{}<>:?"
    }
    ```

*   **`aws_db_instance`:** Creates the RDS MySQL database instance.

    ```terraform
    resource "aws_db_instance" "default" {
      allocated_storage           = var.db_allocated_storage
      engine                      = "mysql"
      engine_version              = "8.0"
      instance_class              = var.db_instance_type
      db_name                     = var.db_name
      username                    = var.db_user
      password                    = data.aws_secretsmanager_secret_version.db_password.secret_string # Use the secret from Secrets Manager
      parameter_group_name        = aws_db_parameter_group.default.name # Use the custom parameter group
      db_subnet_group_name        = aws_db_subnet_group.db_subnet_group.name
      vpc_security_group_ids    = [aws_security_group.allow_mysql.id]
      skip_final_snapshot      = var.db_skip_final_snapshot
      final_snapshot_identifier = "wordpress-db-snapshot-${random_string.random.result}"
      multi_az                    = true
      backup_retention_period     = var.db_backup_retention_period
      performance_insights_enabled  = var.db_performance_insights_enabled
      performance_insights_retention_period = var.db_performance_insights_retention_period
      monitoring_interval         = var.db_monitoring_interval
      monitoring_role_arn         = aws_iam_role.rds_monitoring_role.arn
      storage_type                = "gp3"
      storage_encrypted           = true
      publicly_accessible         = false

      tags = {
        Name = "wordpress-db-${random_string.random.result}"
      }

      lifecycle {
        create_before_destroy = true
      }
    }
    ```

    *   **Key Attributes:**
        *   `allocated_storage`:  The amount of storage allocated to the database.
        *   `instance_class`: The database instance type.
        *   `db_name`, `username`: The database name and username.
        *   `password`:  Retrieved from AWS Secrets Manager.
        *   `vpc_security_group_ids`:  The security groups associated with the database.
        *   `multi_az`:  Enables Multi-AZ deployment for high availability.
        *   `skip_final_snapshot`:  Determines whether a final snapshot is created when the database is destroyed.
        *   `performance_insights_enabled`, `performance_insights_retention_period`: Enables and configures RDS Performance Insights for monitoring.
        *   `monitoring_interval`, `monitoring_role_arn`: Configures RDS Enhanced Monitoring.
    *   **Important:**  The `lifecycle` block with `create_before_destroy = true` ensures that a new database instance is created before the old one is destroyed during updates, minimizing downtime.
    *   **Customization**:  Customize the `instance_class`, `allocated_storage`, `multi_az`, `backup_retention_period`, `performance_insights_enabled`, and `monitoring_interval` based on your requirements.

*   **`aws_db_parameter_group`:** Creates a custom database parameter group to configure database settings, in this case, slow query logging.

    ```terraform
    resource "aws_db_parameter_group" "default" {
      name   = "wordpress-db-params-${random_string.random.result}"
      family = "mysql8.0"

      parameter {
        name  = "slow_query_log"
        value = "1"
      }

      parameter {
        name  = "long_query_time"
        value = "5" # Log queries taking longer than 5 seconds
      }

      description = "Custom parameter group for WordPress"
    }
    ```

    *   **Customization:**  You can add or modify parameters to fine-tune the database configuration. For example, you can adjust buffer sizes, connection limits, or character sets.  Ensure the `family` attribute matches the database engine version.

*   **`aws_lb`:** Creates the Application Load Balancer (ALB) to distribute traffic across the EC2 instances.

    ```terraform
    resource "aws_lb" "main" {
      name               = "wordpress-alb-${random_string.random.result}"
      internal           = false
      load_balancer_type = "application"
      security_groups    = [aws_security_group.allow_http_https.id]
      subnets            = [aws_subnet.public_subnet_a.id, aws_subnet.public_subnet_b.id]
      idle_timeout = 60

      tags = {
        Name = "wordpress-alb-${random_string.random.result}"
      }
    }
    ```

    *   **Key Attributes:**
        *   `internal`:  Specifies whether the ALB is internal or external (internet-facing).
        *   `load_balancer_type`:  Set to "application" for an Application Load Balancer.
        *   `security_groups`:  The security groups associated with the ALB.
        *   `subnets`:  The subnets where the ALB will be created.
        *   `idle_timeout`: The idle timeout value for connections to the ALB.
    *   **Customization:**  Adjust the `idle_timeout` based on your application's needs. For WebSocket applications, you'll need to increase this value.

*   **`aws_wafv2_web_acl` and `aws_wafv2_web_acl_association`:** Creates a WAFv2 Web ACL and associates it with the ALB to protect against web exploits.

    ```terraform
    resource "aws_wafv2_web_acl" "example" {
      name        = "ExampleWebACL-${random_string.random.result}"
      description = "A WebACL for WordPress Application"
      scope       = "REGIONAL"
      default_action {
        allow {}
      }
      visibility_config {
        cloudwatch_metrics_enabled = false
        metric_name                = "friendly-name-associated-with-the-web-acl"
        sampled_requests_enabled = false
      }
    }

    resource "aws_wafv2_web_acl_association" "example" {
      resource_arn = aws_lb.main.arn
      web_acl_arn  = aws_wafv2_web_acl.example.arn
    }
    ```

    *   **Customization:** The `default_action` is currently set to `allow {}`, which means all requests are allowed. This is NOT recommended for production. You'll need to define rules to block malicious traffic. Consider using AWS Managed Rules for common web exploits.  Enable `cloudwatch_metrics_enabled` and `sampled_requests_enabled` for monitoring.

*   **`aws_lb_target_group`:** Creates a target group for the ALB, defining the set of EC2 instances that the ALB will distribute traffic to.

    ```terraform
    resource "aws_lb_target_group" "main" {
      name        = "wordpress-tg-${random_string.random.result}"
      port        = 80
      protocol    = "HTTP"
      vpc_id      = aws_vpc.main.id
      target_type = "instance"

      health_check {
        path                = "/"  # Change to root path for initial check
        port                = "traffic-port"
        protocol            = "HTTP"
        matcher             = "200-399"
        interval            = 30
        timeout             = 5
        healthy_threshold   = 2
        unhealthy_threshold = 2
      }
    }
    ```

    *   **Key Attributes:**
        *   `port`: The port on which the EC2 instances are listening.
        *   `protocol`: The protocol used by the EC2 instances.
        *   `vpc_id`:  The VPC ID.
        *   `target_type`:  The type of target (in this case, "instance").
        *   `health_check`:  Configures health checks to ensure that the EC2 instances are healthy.
    *   **Customization:** Adjust the `health_check` settings to match your application's health check endpoint.  A `200-399` matcher is common for HTTP applications.

*   **`aws_lb_listener`:** Creates listeners for the ALB, configuring it to listen on HTTP (redirects to HTTPS) and HTTPS ports.

    ```terraform
    resource "aws_lb_listener" "https" {
      load_balancer_arn = aws_lb.main.arn
      port              = 443
      protocol          = "HTTPS"
      ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01" # Use the latest security policy
      certificate_arn   = aws_acm_certificate.example.arn

      default_action {
        type             = "forward"
        target_group_arn = aws_lb_target_group.main.arn
      }
    }

    resource "aws_lb_listener" "http" {
      load_balancer_arn = aws_lb.main.arn
      port              = 80
      protocol          = "HTTP"

      default_action {
        type = "redirect"

        redirect {
          port        = "443"
          protocol    = "HTTPS"
          status_code = "HTTP_301"
        }
      }
    }
    ```

    *   **Customization:** The `ssl_policy` should be set to the latest security policy.
    *   **Important:**  The HTTP listener redirects all traffic to HTTPS.

*   **`data "aws_route53_zone"`:** Retrieves information about the Route 53 zone for your domain.

    ```terraform
    data "aws_route53_zone" "selected" {
      name         = "aws.italiadns.net."
      private_zone = false
    }
    ```

    *   **Customization:**  Replace `"aws.italiadns.net."` with your registered domain name.
    *  **Important:** Ensure that the domain is properly delegated to AWS Name Servers.

*   **`aws_acm_certificate`:** Creates an ACM certificate for SSL/TLS encryption.

    ```terraform
    resource "aws_acm_certificate" "example" {
      domain_name               = var.domain_name
      validation_method         = "DNS"

      tags = {
        Name = "SSL Certificate-${random_string.random.result}"
      }

      lifecycle {
        create_before_destroy = true
      }
    }
    ```

    *   **Key Attributes:**
        *   `domain_name`:  The domain name for the certificate.
        *   `validation_method`:  Set to "DNS" for DNS validation.
    *   **Important:** The `lifecycle` block with `create_before_destroy = true` allows recreation of certificate before destroy during updates.

*   **`aws_route53_record` (DNS Validation and WordPress Site):** Creates DNS records in Route 53 for certificate validation and to point the domain name to the ALB.

    ```terraform
    resource "aws_route53_record" "example_validation" {
      for_each = { for dvo in aws_acm_certificate.example.domain_validation_options : dvo.domain_name => dvo }

      zone_id         = data.aws_route53_zone.selected.zone_id
      name            = each.value.resource_record_name
      type            = each.value.resource_record_type
      records         = [each.value.resource_record_value]
      ttl             = 60
    }

    resource "aws_route53_record" "wordpress_site" {
      zone_id = data.aws_route53_zone.selected.zone_id
      name    = var.domain_name
      type    = "A"

      alias {
        name                   = aws_lb.main.dns_name
        zone_id                = aws_lb.main.zone_id
        evaluate_target_health = true
      }
    }
    ```

    *   **Important:** The `aws_route53_record.example_validation` record are necessary to validate the ACM certificate. These are created using `for_each` and `aws_acm_certificate.example.domain_validation_options`.  Ensure that these records are created correctly and that DNS propagation has completed.
    *   The `aws_route53_record.wordpress_site` creates an A record that points the domain name to the ALB.
        *   `evaluate_target_health = true` ensures that Route 53 only returns the ALB's IP address if the ALB is healthy.

*   **`aws_launch_template`:** Defines the configuration for the EC2 instances.

    ```terraform
    resource "aws_launch_template" "wordpress_lt" {
      name_prefix   = "wordpress-lt-${random_string.random.result}-"
      image_id      = var.ami_id
      instance_type = var.instance_type
      key_name      = var.key_name

      vpc_security_group_ids = [aws_security_group.allow_http_https.id, aws_security_group.ec2_sg.id] # <--- IMPORTANT: Use the correct ec2 sg here.  If allow_http_https has outbound access already it may not be necessary to include here.

      iam_instance_profile {
        arn = aws_iam_instance_profile.ec2_instance_profile.arn
      }

      user_data = base64encode(templatefile("${path.module}/userdata.tpl", {
        db_name     = aws_db_instance.default.db_name
        db_user     = aws_db_instance.default.username
        db_host     = aws_db_instance.default.endpoint
        domain_name = var.domain_name
        secrets_wp_admin_arn = aws_secretsmanager_secret.wp_admin_creds.arn
        secrets_db_password_arn = aws_secretsmanager_secret.db_password.arn
        db_password = data.aws_secretsmanager_secret_version.db_password.secret_string
        wp_admin_creds = data.aws_secretsmanager_secret_version.wp_admin_creds.secret_string  # Add this line
      }))

      tags = {
        Name = "wordpress-lt-${random_string.random.result}"
      }

      lifecycle {
        create_before_destroy = true
      }
    }
    ```

    *   **Key Attributes:**
        *   `image_id`:  The AMI ID for the EC2 instances.
        *   `instance_type`:  The EC2 instance type.
        *   `key_name`:  The SSH key pair to use for the EC2 instances.
        *   `vpc_security_group_ids`: The security groups associated with the EC2 instances. **Crucially, both the `allow_http_https` and `ec2_sg` are attached to the instances.  This allows outbound traffic from the EC2 instances to the internet and inbound traffic from the ALB.**
        *   `iam_instance_profile`:  The IAM instance profile to use for the EC2 instances.
        *   `user_data`:  A script that is executed when the EC2 instance is launched.  This script is used to install WordPress and configure the database connection.  The `templatefile` function is used to render the `userdata.tpl` file with the necessary variables.
    *   **Important**: Be very careful about outbound access configured for the `allow_http_https` security group.  If all outbound traffic is blocked, you will also need to allow outbound access to the internet using the security group attached to the launch template.

```markdown
*   **`aws_autoscaling_group`:** Creates an Auto Scaling Group (ASG) to automatically scale the number of EC2 instances based on traffic.

    ```terraform
    resource "aws_autoscaling_group" "wordpress_asg" {
     name                 = "wordpress-asg-${random_string.random.result}"
     vpc_zone_identifier  = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
     desired_capacity     = var.desired_capacity
     max_size             = var.max_size
     min_size             = var.min_size
     health_check_type    = "ELB"
     health_check_grace_period = var.default_instance_warmup
       target_group_arns = [aws_lb_target_group.main.arn]

     launch_template {
       id      = aws_launch_template.wordpress_lt.id
       version = "$Latest" # Or a specific version
     }
    }
    ```

    *   **Key Attributes:**
        *   `vpc_zone_identifier`:  The subnets where the EC2 instances will be launched.  **Crucially, these are the *private* subnets.**
        *   `desired_capacity`, `max_size`, `min_size`:  The desired, maximum, and minimum number of EC2 instances.
        *   `health_check_type`: The type of health check to use. "ELB" indicates that the ALB's health checks will be used.
        *   `health_check_grace_period`:  The amount of time (in seconds) that the ASG will wait before performing health checks on new instances.  This allows the instances to boot and configure themselves before being checked.  Important to set a reasonable value.
        *   `launch_template`:  Specifies the launch template to use for the EC2 instances.
    *   **Customization:** Adjust `desired_capacity`, `max_size`, `min_size`, and `health_check_grace_period` based on your application's requirements. Use a specific Launch Template version instead of `$Latest` in production to prevent unexpected changes during ASG scaling events.

*   **`aws_autoscaling_policy`:** Creates Auto Scaling policies to automatically scale the number of EC2 instances based on CPU utilization.

    ```terraform
    resource "aws_autoscaling_policy" "scale_up" {
      name                   = "scale-up-${random_string.random.result}"
      autoscaling_group_name = aws_autoscaling_group.wordpress_asg.name
      policy_type           = "TargetTrackingScaling"

      target_tracking_configuration {
        predefined_metric_specification {
          predefined_metric_type = "ASGAverageCPUUtilization"
        }
        target_value = 70.0
      }
    }

    resource "aws_autoscaling_policy" "scale_down" {
      name                   = "scale-down-${random_string.random.result}"
      autoscaling_group_name = aws_autoscaling_group.wordpress_asg.name
      policy_type           = "TargetTrackingScaling"

      target_tracking_configuration {
        predefined_metric_specification {
          predefined_metric_type = "ASGAverageCPUUtilization"
        }
        target_value = 30.0
      }
    }
    ```

    *   **Key Attributes:**
        *   `autoscaling_group_name`:  The name of the Auto Scaling Group to which the policy applies.
        *   `policy_type`:  Set to "TargetTrackingScaling" for target tracking policies.
        *   `target_tracking_configuration`:  Configures the target tracking policy.
            *   `predefined_metric_specification`:  Specifies the metric to track.
            *   `target_value`: The target value for the metric.
    *   **Customization:**  Adjust `target_value` based on your application's performance requirements. You can also use custom metrics and scaling policies. Consider using Step Scaling policies for more granular control.

*   **`aws_iam_role` and `aws_iam_instance_profile` (EC2):** Creates an IAM role and instance profile for the EC2 instances, granting them the necessary permissions to access other AWS resources.

    ```terraform
    resource "aws_iam_role" "ec2_role" {
      name = "ec2-wordpress-role-${random_string.random.result}"

      assume_role_policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
          {
            Action = "sts:AssumeRole",
            Principal = {
              Service = "ec2.amazonaws.com"
            },
            Effect = "Allow",
            Sid = ""
          }
        ]
      })
    }

    resource "aws_iam_instance_profile" "ec2_instance_profile" {
      name = "ec2-wordpress-instance-profile-${random_string.random.result}"
      role = aws_iam_role.ec2_role.name
    }
    ```

    *   **Important:** The `assume_role_policy` allows EC2 instances to assume this role.

*   **`aws_iam_role_policy_attachment`:** Attaches the `AmazonSSMManagedInstanceCore` policy to the EC2 IAM role, allowing the instances to be managed by AWS Systems Manager (SSM).

    ```terraform
    resource "aws_iam_role_policy_attachment" "example-attach" {
      policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      role       = aws_iam_role.ec2_role.name
    }
    ```
   * **Important**: Enables SSM for remote management.

*   **`aws_iam_role_policy` (Secrets Manager):** Creates an IAM policy to allow the EC2 instances to access AWS Secrets Manager to retrieve the database password.

    ```terraform
    resource "aws_iam_role_policy" "secretsmanager_policy" {
      name   = "secretsmanager-access-${random_string.random.result}"
      role   = aws_iam_role.ec2_role.id
      policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
          {
            Action = [
              "secretsmanager:GetSecretValue",
              "secretsmanager:DescribeSecret"
            ],
            Effect   = "Allow",
            Resource = [
              aws_secretsmanager_secret.db_password.arn,
              aws_secretsmanager_secret.wp_admin_creds.arn
            ]
          }
        ]
      })
    }
    ```

    *   **Important:**  This policy grants the necessary permissions to retrieve the secrets from Secrets Manager.

*   **`aws_iam_role` and `aws_iam_role_policy` (RDS Monitoring):** Creates an IAM role and policy for RDS Enhanced Monitoring, allowing CloudWatch Logs to access RDS metrics.

    ```terraform
    resource "aws_iam_role" "rds_monitoring_role" {
      name = "rds-monitoring-role-${random_string.random.result}"

      assume_role_policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
          {
            Action = "sts:AssumeRole",
            Principal = {
              Service = "monitoring.rds.amazonaws.com"
            },
            Effect = "Allow",
            Sid = ""
          }
        ]
      })
    }

    resource "aws_iam_role_policy" "rds_monitoring_policy" {
      name   = "rds-monitoring-policy-${random_string.random.result}"
      role   = aws_iam_role.rds_monitoring_role.id
      policy = jsonencode({
        Version = "2012-10-17",
        Statement = [
          {
            Action = [
              "logs:PutLogEvents",
              "logs:GetLogEvents",
              "logs:CreateLogGroup",
              "logs:CreateLogStream",
              "logs:DescribeLogStreams",
              "logs:DescribeLogGroups"
            ],
            Effect = "Allow",
            Resource = "*"
          }
        ]
      })
    }
    ```

    *   **Important:** This enables Enhanced Monitoring.

*   **`aws_cloudwatch_log_group`:** Creates a CloudWatch Log Group to store logs from the EC2 instances.

    ```terraform
    resource "aws_cloudwatch_log_group" "wordpress" {
      name              = "/aws/ec2/wordpress-${random_string.random.result}"
      retention_in_days = 7
    }
    ```

    *   **Customization:** Adjust the `retention_in_days` based on your logging requirements.

*   **`aws_cloudfront_distribution`:** Creates a CloudFront distribution to improve performance by caching static content.

    ```terraform
    resource "aws_cloudfront_distribution" "s3_distribution" {
      origin {
        domain_name = aws_lb.main.dns_name
        origin_id   = "LB"

        custom_origin_config {
          http_port                = 80
          https_port               = 443
          origin_protocol_policy = "https-only"
          origin_ssl_protocols   = ["TLSv1.2"]
        }
      }

      enabled         = true
      is_ipv6_enabled = true
      default_root_object = "index.php"

      default_cache_behavior {
        allowed_methods  = ["GET", "HEAD"]
        cached_methods   = ["GET", "HEAD"]
        target_origin_id = "LB"
        viewer_protocol_policy = "redirect-to-https"

        forwarded_values {
          query_string = false
          cookies {
            forward = "none"
          }
        }
        min_ttl                = 0
        default_ttl            = 3600
        max_ttl                = 86400
      }

      restrictions {
        geo_restriction {
          restriction_type = "none"
        }
      }

      viewer_certificate {
        cloudfront_default_certificate = true
      }

      tags = {
        Environment = "production"
      }
    }
    ```

    *   **Key Attributes:**
        *   `origin`:  Specifies the origin server (in this case, the ALB).
            * `origin_protocol_policy` = "https-only" enforces the origin connection over HTTPS.
        *   `default_cache_behavior`:  Configures the default caching behavior.
            * `viewer_protocol_policy` = "redirect-to-https" configures redirections from http to https
        *   `viewer_certificate`:  Specifies the SSL/TLS certificate to use.
    *   **Customization:** Configure caching behavior, allowed HTTP methods, and other settings based on your application's requirements.  Consider using an Origin Access Identity (OAI) to restrict direct access to the S3 bucket (if you are serving media from S3).
    *    **Important:** Setting the `domain_name` for the `origin` directly to the LB may present security risks, as it exposes the internal LB to the internet. It's typically preferable to either serve static assets through an S3 bucket with restricted access, or use Lambda@Edge to authenticate requests to the LB if more dynamic origin interaction is needed.

*   **`aws_secretsmanager_secret` (WordPress Admin Credentials):** Creates a secret in AWS Secrets Manager to store the WordPress administrator credentials.

    ```terraform
    resource "aws_secretsmanager_secret" "wp_admin_creds" {
      name                    = "wp-admin-creds-${random_string.random.result}"
      description            = "WordPress admin credentials"
      recovery_window_in_days = 7
    }
    ```

*   **`random_password` (WordPress Admin Password):** Generates a random password for the WordPress administrator account.

    ```terraform
        resource "random_password" "wp_admin_password" {
      length           = 16
      special          = true
      override_special = "!#$%&*()-_=+[]{}<>:?"
    }
    ```

*    **`aws_secretsmanager_secret_version` (WordPress Admin Credentials):** Creates a secret in AWS Secrets Manager with username, password and email of WP Admin.

    ```terraform
       resource "aws_secretsmanager_secret_version" "wp_admin_creds" {
      secret_id     = aws_secretsmanager_secret.wp_admin_creds.id
      secret_string = jsonencode({
        username = var.wp_admin_username
        password = random_password.wp_admin_password.result
        email    = var.wp_admin_email
      })
    }
    ```

## Understanding the `userdata.tpl` file

The `userdata.tpl` file contains a script that is executed when the EC2 instance is launched.  This script automates the following tasks:

*   Updates the package list and installs necessary tools (Apache, PHP, MySQL client, `wp-cli`, etc.).
*   Starts and enables Apache.
*   Installs `wp-cli` (WordPress command-line interface).
*   Downloads and extracts WordPress.
*   Creates the `wp-config.php` file using `wp-cli` and the database credentials from AWS Secrets Manager.
*   Installs WordPress using `wp-cli`.
*   Configures Apache with a proper Virtual Host.
*   Configures SELinux.
*   Restarts Apache.
*   Configure .htaccess to WordPress
*   Enable mod_rewrite

**Important:** This script logs all output to `/tmp/userdata.log`.  If you encounter any issues with the WordPress installation, check this file for errors.

**Security:** This script is designed to be a starting point for automating the WordPress installation. For a production environment, you may want to use a configuration management tool such as Ansible or Chef to improve security and manageability.

**Customization:** You can customize the `userdata.tpl` file to install additional software, configure WordPress plugins, or perform other tasks.

## Outputs

The `outputs.tf` file defines the output values that will be displayed after the deployment.  These outputs provide important information such as:

*   `load_balancer_url`: The URL of the Application Load Balancer (ALB).
*   `database_endpoint`: The endpoint of the MySQL database.
*   `cloudfront_domain`: The domain name of the CloudFront distribution.
*   `cloudfront_test_url`: Test URL for the CloudFront distribution (HTTPS).
*   `loadbalancer_test_url`: Test URL for the Load Balancer (HTTP). This will redirect to HTTPS.
*   `loadbalancer_https_test_url`: Test URL for the Load Balancer (HTTPS).
*  `custom_domain_name`: The custom domain name used for the WordPress site.

## Security Considerations

*   **Database and Admin Passwords:** The database and WordPress admin passwords are automatically generated and stored in AWS Secrets Manager. Ensure that the IAM role used by the EC2 instances has the necessary permissions to access Secrets Manager.
*   **Security Groups:** The security groups are configured to allow HTTP and HTTPS traffic from the internet and MySQL traffic from the EC2 instances.  **Critically, a dedicated security group (`ec2_sg`) allows HTTP traffic from the ALB to the EC2 instances.**  Review and adjust the security groups as needed. Consider restricting access to specific IP addresses (using the `allowed_inbound_cidr_blocks` variable).
*   **IAM Roles:** The IAM roles grant the EC2 instances the necessary permissions to access other AWS resources. Review and restrict the IAM roles to follow the principle of least privilege.
*   **WAFv2:** The WAFv2 Web ACL is a basic configuration. Customize the rules to provide more comprehensive protection against web exploits.
*   **RDS Enhanced Monitoring:** Consider enabling Enhanced Monitoring for production environments for deeper database performance insights. If enabling, ensure the IAM role has the required permissions.  **Note:** This deployment currently does enable this feature if you set `db_monitoring_interval` variable.
*   **Regular Security Updates:** It is your responsibility to keep the underlying operating system (Amazon Linux 2) and WordPress installation up-to-date with the latest security patches.  Automated security updates are highly recommended.
*   **Restrict Inbound Access:** Restrict the `allowed_inbound_cidr_blocks` to only the necessary IP addresses or CIDR blocks.
*   **Final Database Snapshot:**  Set `db_skip_final_snapshot` to `false` for production environments to ensure a backup is created before the database is deleted.
*   **HTTPS Enforcement:** The ALB is configured to redirect all HTTP traffic to HTTPS, ensuring that all communication is encrypted.

## Cleanup

To destroy the infrastructure created by Terraform:

```bash
terraform destroy
```

Type `yes` to confirm. This will delete all resources created by the Terraform configuration.

## Troubleshooting

*   **Errors During `terraform apply`:** Carefully examine the error messages. Common causes include:
    *   Incorrect AMI ID. **Verify the AMI ID is valid in your target AWS region!**
    *   Missing or invalid AWS credentials.
    *   Insufficient IAM permissions.
    *   Resource naming conflicts.
    *   Invalid variable values.
    *   ACM Certificate Validation Failed: Verify that the Route53 records have been created correctly and that DNS propagation has completed.
*   **WordPress Site Not Accessible:**
    *   Check the security groups to ensure that HTTP and HTTPS traffic is allowed between the ALB and EC2 instances.  Verify that the `ec2_sg` is correctly configured.
    *   Verify that the EC2 instances are running and healthy in the Target Group.  **A "502 Bad Gateway" error strongly suggests a problem with the security group configuration or the health of the EC2 instances.**
    *   Check the ALB listeners and target group configuration.
    *   Examine the CloudWatch logs for any errors.
    *   Ensure that the Route 53 records are correctly configured and have propagated.
    *   If using CloudFront, ensure that the distribution is enabled and that DNS records point to the CloudFront domain.
*   **EC2 Instance Configuration Issues:**
    *   SSH into an EC2 instance (if you configured a key pair) and examine the `/tmp/userdata.log` file to identify any errors that occurred during the instance initialization. **This is your first stop for troubleshooting EC2 instance setup problems!**
    *   Check the Apache error logs for any WordPress-related errors (`/var/log/httpd/error_log`).
    *   Verify that the database connection details in `wp-config.php` are correct.
*   **Automated WordPress Installation Fails:**
    *   Check the `/tmp/userdata.log` for errors related to `wp-cli`.
    *   Ensure that the AWS Secrets Manager secret for the WordPress admin credentials is being retrieved correctly.
    *   Verify that the IAM role for the EC2 instances has permissions to access Secrets Manager.
*   **CloudFront not working properly:**
      * Verify that your CloudFront distribution points to the correct origin, that is your Load Balancer. Also, verify that you created a Custom Origin Config and that the Origin protocol policy is HTTPS only.
      * Verify that there is a DNS A record (alias) that point to the CloudFront distribution.
      * You must wait some minutes before the CloudFront distribution can propagate and work properly.

## Further Enhancements

*   **Centralized Logging:** Implement a centralized logging solution using CloudWatch Logs or other log management tools.
*   **Implement a Backup Strategy:** Implement automatic database backups and EC2 instance snapshots.
*   **CI/CD Pipeline:** Create a CI/CD pipeline to automate the deployment process.
*   **Implement Object Caching:** Use Memcached or Redis for improved performance.
*   **WAFv2 Advanced Configuration:**  Implement more sophisticated WAF rules using AWS Managed Rules or custom rules.

## Advanced Configuration Options

This section details some advanced configuration options that can be customized to fine-tune the deployment. These options can be set as variables in `terraform.tfvars` or overridden on the command line using the `-var` flag.

*   **Custom AMI:** While the project defaults to an Amazon Linux 2 AMI, you can use a custom AMI with pre-installed software or specific configurations.  Be sure to update the `ami_id` variable accordingly.  When using a custom AMI, ensure it has the AWS SSM agent installed and configured correctly to allow for proper instance management.

*   **Enhanced Security Group Rules:** The default security group rules are relatively permissive for demonstration purposes.  For production deployments, consider the following:
    *   **Limit Inbound SSH Access:** Restrict inbound SSH access (`key_name` and the related security group rule) to specific IP addresses or CIDR blocks, or remove it entirely and use AWS Systems Manager Session Manager for secure remote access.
    *   **Implement a Web Application Firewall (WAF):**  Customize the WAFv2 rules to protect against specific threats.  Consider enabling managed rule groups for common web exploits.
    *   **Network ACLs:** Implement Network ACLs (NACLs) on the subnets for an additional layer of security. NACLs are stateless and provide a basic level of traffic filtering.
    *   **TLS Versions and Cipher Suites:** Configure the ALB listener to use specific TLS versions and cipher suites to improve security posture.  This can be achieved using the `alb.tf` file and modifying the listener resources.

*   **Database Configuration:**
    *   **RDS Instance Class:** The default `db_instance_type` (e.g., `db.t3.micro`) is suitable for testing and development. For production environments, choose a more powerful instance class based on your performance requirements.
    *   **RDS Storage:**  Adjust the `allocated_storage` variable to specify the amount of storage allocated to the RDS instance.
    *   **Multi-AZ Deployment:** Enable Multi-AZ deployment for high availability by setting the `multi_az` variable to `true`.  This will create a standby replica of the database in a different Availability Zone.
    *   **Database Encryption:** Ensure that RDS encryption is enabled (it's enabled by default in this configuration).
    *   **DB Parameter Groups:** For advanced database tuning, create and use custom DB Parameter Groups.

*   **Auto Scaling Group (ASG) Configuration:**
    *   **Scaling Policies:**  Define custom scaling policies for the ASG based on CPU utilization, network traffic, or other metrics.  This allows you to automatically scale the number of EC2 instances based on the actual workload. Consider using Predictive Scaling.
    *   **Lifecycle Hooks:** Implement lifecycle hooks to perform custom actions during instance launch or termination.  This can be useful for tasks such as registering instances with a service discovery system or cleaning up resources when an instance is terminated.
    *   **Instance Refresh:** Use Instance Refresh to gracefully roll out new versions of your application to the ASG.

*   **CloudFront Customization:**
    *   **Cache Policies:** Configure custom cache policies for CloudFront to optimize caching behavior.  This can significantly improve performance by reducing the load on the origin server.
    *   **Origin Access Identity (OAI):** Use an OAI to restrict access to the S3 bucket used for the WordPress media library. This ensures that users can only access the media files through CloudFront.
    *   **Custom Error Pages:** Create custom error pages for CloudFront to provide a better user experience in case of errors.

*   **Monitoring and Logging:**
    *   **CloudWatch Alarms:** Create CloudWatch alarms to monitor the health of your infrastructure and receive notifications when issues arise.
    *   **Detailed Monitoring:** Enable detailed monitoring on the EC2 instances for more granular performance metrics.
    *   **RDS Performance Insights:** Enable RDS Performance Insights for advanced database performance analysis and troubleshooting.
    *   **Centralized Log Aggregation:**  Use a centralized log aggregation service such as Amazon Elasticsearch Service (now OpenSearch Service) or a third-party solution to collect and analyze logs from all components of the application.

*   **WordPress Configuration:**
    *   **Object Cache:** Implement an object cache such as Memcached or Redis to improve WordPress performance.  This can be done by installing the necessary software on the EC2 instances and configuring WordPress to use the cache.
    *   **CDN Integration:** Configure WordPress to use the CloudFront CDN for serving static assets.  This can be done using a WordPress plugin such as W3 Total Cache or WP Super Cache.
    *   **WordPress Hardening:** Implement various WordPress hardening techniques to improve security.  This includes disabling file editing, hiding the WordPress version number, and using strong passwords.

## Known Issues

*   **Slow Initial Deployment:** The initial deployment can take a considerable amount of time, especially the creation of the RDS instance and the ACM certificate validation.
*   **`userdata.tpl` Complexity:** The `userdata.tpl` file can become complex and difficult to manage.  Consider using a configuration management tool such as Ansible or Chef to simplify instance configuration.
*   **Database Password Rotation:** The database password is automatically generated and stored in Secrets Manager.  Implement a mechanism to automatically rotate the database password on a regular basis.
*   **Security Group Changes Require Replacement**: Any time you change the security group rules the underlying resources will need to be recreated, which will cause downtime, so make sure your configurations are correct.
*   **`wp-config.php` Hardcoded Paths**: The paths used in `wp-config.php` may not be compatible with all custom WordPress setups. It's possible you need to adjust them to fit your specific needs.

This documentation provides a comprehensive overview of the Terraform WordPress deployment on AWS, including prerequisites, getting started instructions, security considerations, troubleshooting tips, further enhancements, contributing guidelines, and advanced configuration options. By following these guidelines, you can successfully deploy and manage a highly available and secure WordPress website on AWS. Remember to always prioritize security best practices and regularly review and update your infrastructure to stay ahead of potential threats.
