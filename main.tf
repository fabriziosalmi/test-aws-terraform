# main.tf

# Random String for Unique Resource Names
resource "random_string" "random" {
  length  = 8
  special = false
  upper   = false
}

# Local Variables
locals {
  cidr_block = "10.0.0.0/16"
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = local.cidr_block
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "wordpress-vpc-${random_string.random.result}"
  }
}

# Public Subnets
resource "aws_subnet" "public_subnet_a" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(local.cidr_block, 8, 1)
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false # Important: set false to force NAT Gateway usage

  tags = {
    Name = "public-subnet-a-${random_string.random.result}"
  }
}

resource "aws_subnet" "public_subnet_b" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(local.cidr_block, 8, 2) # Correct CIDR block
  availability_zone       = "${var.aws_region}b" # Correct Availability Zone
  map_public_ip_on_launch = false # Important: set false to force NAT Gateway usage

  tags = {
    Name = "public-subnet-b-${random_string.random.result}"
  }
}

# Private Subnets
resource "aws_subnet" "private_subnet_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(local.cidr_block, 8, 11)
  availability_zone = "${var.aws_region}a"

  tags = {
    Name = "private-subnet-a-${random_string.random.result}"
  }
}

resource "aws_subnet" "private_subnet_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(local.cidr_block, 8, 12)
  availability_zone = "${var.aws_region}b"

  tags = {
    Name = "private-subnet-b-${random_string.random.result}"
  }
}

# Internet Gateway
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wordpress-igw-${random_string.random.result}"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "wordpress-natgw-eip-${random_string.random.result}"
  }
}

# NAT Gateway (in public subnet)
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public_subnet_a.id # Or b

  tags = {
    Name = "wordpress-natgw-${random_string.random.result}"
  }

  depends_on = [aws_internet_gateway.gw] # Important dependency
}

# Public Route Table
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

# Private Route Table
resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "private-route-table-${random_string.random.result}"
  }
}

# Route Table Associations
resource "aws_route_table_association" "public_subnet_a" {
  subnet_id      = aws_subnet.public_subnet_a.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "public_subnet_b" {
  subnet_id      = aws_subnet.public_subnet_b.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "private_subnet_a" {
  subnet_id      = aws_subnet.private_subnet_a.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_route_table_association" "private_subnet_b" {
  subnet_id      = aws_subnet.private_subnet_b.id
  route_table_id = aws_route_table.private_route_table.id
}

# Security Groups
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

# Security Group for HTTP/HTTPS Traffic (ALB)
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

# Security Group for MySQL Traffic (RDS)
resource "aws_security_group" "allow_mysql" {
  name        = "allow_mysql-${random_string.random.result}"
  description = "Allow MySQL traffic from EC2 instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]  # <--- IMPORTANT: Allow MySQL from the EC2 security group, not the ALB
    description = "Allow MySQL from app servers (EC2 SG)"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "allow_mysql-${random_string.random.result}"
  }
}

# Database Subnet Group
resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "db-subnet-group-${random_string.random.result}"
  subnet_ids = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]

  tags = {
    Name = "DB Subnet Group-${random_string.random.result}"
  }
}

# Secrets Manager

# Secret for Database Password
resource "aws_secretsmanager_secret" "db_password" {
  name                    = "wp-db-pass-${random_string.random.result}"
  description            = "Password for the WordPress database"
  recovery_window_in_days = 7
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db_password.result # Use the random_password result

  depends_on = [aws_secretsmanager_secret.db_password, random_password.db_password] # Create order
}

# Data source to retrieve the secret value.
data "aws_secretsmanager_secret_version" "db_password" {
  secret_id = aws_secretsmanager_secret.db_password.id
  depends_on = [aws_secretsmanager_secret_version.db_password] # Ensure version is created.
}

# Random Password Generator
resource "random_password" "db_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# RDS Instance
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

# RDS Parameter Group for Slow Query Logging
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

# Application Load Balancer
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

# WAFv2 Web ACL
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

# Target Group
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

# HTTPS Listener
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

# HTTP Listener (Redirect to HTTPS)
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

# Route53 DNS Zone Lookup
data "aws_route53_zone" "selected" {
  name         = "aws.italiadns.net."
  private_zone = false
}

# ACM Certificate
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

# DNS Validation Records
resource "aws_route53_record" "example_validation" {
  for_each = { for dvo in aws_acm_certificate.example.domain_validation_options : dvo.domain_name => dvo }

  zone_id         = data.aws_route53_zone.selected.zone_id
  name            = each.value.resource_record_name
  type            = each.value.resource_record_type
  records         = [each.value.resource_record_value]
  ttl             = 60
}

# Certificate Validation
resource "aws_acm_certificate_validation" "example" {
  certificate_arn         = aws_acm_certificate.example.arn
  validation_record_fqdns = [for record in aws_route53_record.example_validation : record.fqdn]

  depends_on = [aws_route53_record.example_validation]
}

# Route53 A Record for WordPress Site
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

# Launch Template
resource "aws_launch_template" "wordpress_lt" {
  name_prefix   = "wordpress-lt-${random_string.random.result}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.ec2_sg.id] # <--- Use only the EC2 security group

  iam_instance_profile {
    arn = aws_iam_instance_profile.ec2_instance_profile.arn
  }

  user_data = base64encode(templatefile("${path.module}/userdata.tpl", {
    db_name                = aws_db_instance.default.db_name
    db_user                = aws_db_instance.default.username
    db_host                = aws_db_instance.default.endpoint
    domain_name            = var.domain_name
    secrets_wp_admin_arn   = aws_secretsmanager_secret.wp_admin_creds.arn
    secrets_db_password_arn = aws_secretsmanager_secret.db_password.arn
    db_password            = tostring(data.aws_secretsmanager_secret_version.db_password.secret_string)
    wp_admin_creds         = tostring(data.aws_secretsmanager_secret_version.wp_admin_creds.secret_string)
    db_creds               = jsonencode({
                              dbname   = aws_db_instance.default.db_name,
                              username = aws_db_instance.default.username,
                              password = tostring(data.aws_secretsmanager_secret_version.db_password.secret_string),
                              host     = aws_db_instance.default.endpoint
                            })
  }))

  tags = {
    Name = "wordpress-lt-${random_string.random.result}"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "wordpress_asg" {
  name                = "wordpress-asg-${random_string.random.result}"
  max_size            = var.max_size
  min_size            = var.min_size
  desired_capacity    = var.desired_capacity
  vpc_zone_identifier = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
  target_group_arns   = [aws_lb_target_group.main.arn]
  health_check_type   = "ELB"
  health_check_grace_period = var.default_instance_warmup

  launch_template {
    id      = aws_launch_template.wordpress_lt.id
    version = "$Latest"
  }

}

# Auto Scaling Policies
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

# IAM Role for EC2 Instances
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

# Attach SSM Managed Instance Core Policy
resource "aws_iam_role_policy_attachment" "example-attach" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.ec2_role.name
}

# IAM Policy for Secrets Manager Access
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

# IAM Role for RDS Enhanced Monitoring
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

# IAM Policy for CloudWatch Logs Access for RDS Monitoring
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

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "wordpress" {
  name              = "/aws/ec2/wordpress-${random_string.random.result}"
  retention_in_days = 7
}

# CloudFront Distribution
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

# WordPress Admin Credentials in Secrets Manager
resource "aws_secretsmanager_secret" "wp_admin_creds" {
  name                    = "wp-admin-creds-${random_string.random.result}"
  description            = "WordPress admin credentials"
  recovery_window_in_days = 7
}

resource "random_password" "wp_admin_password" {
  length           = 16
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

resource "aws_secretsmanager_secret_version" "wp_admin_creds" {
  secret_id     = aws_secretsmanager_secret.wp_admin_creds.id
  secret_string = jsonencode({
    username = var.wp_admin_username
    password = random_password.wp_admin_password.result
    email    = var.wp_admin_email
  })
}

# Data source to retrieve the secret value
data "aws_secretsmanager_secret_version" "wp_admin_creds" {
  secret_id = aws_secretsmanager_secret.wp_admin_creds.id
  depends_on = [aws_secretsmanager_secret_version.wp_admin_creds]
}

# VPC Endpoints for SSM

resource "aws_vpc_endpoint" "ssm" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type = "Interface"

  subnet_ids         = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
  security_group_ids = [aws_security_group.vpc_endpoint.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ssmmessages" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type = "Interface"

  subnet_ids         = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
  security_group_ids = [aws_security_group.vpc_endpoint.id]
  private_dns_enabled = true
}

resource "aws_vpc_endpoint" "ec2messages" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type = "Interface"

  subnet_ids         = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
  security_group_ids = [aws_security_group.vpc_endpoint.id]
  private_dns_enabled = true
}
#Optional endpoint if ec2 messages doesn't work
#resource "aws_vpc_endpoint" "ec2" {
#  vpc_id            = aws_vpc.main.id
#  service_name      = "com.amazonaws.${var.aws_region}.ec2"
#  vpc_endpoint_type = "Interface"
#
#  subnet_ids         = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
#  security_group_ids = [aws_security_group.vpc_endpoint.id]
#  private_dns_enabled = true
#}
# Optional S3 endpoint if userdata downloads SSM agent packages
#resource "aws_vpc_endpoint" "s3" {
#  vpc_id            = aws_vpc.main.id
#  service_name      = "com.amazonaws.${var.aws_region}.s3"
#  vpc_endpoint_type = "Gateway" # MUST be Gateway type
#  route_table_ids = [aws_route_table.private_route_table.id]
#}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoint" {
  name        = "vpc-endpoint-sg-${random_string.random.result}"
  description = "Security group for VPC Endpoints"
  vpc_id      = aws_vpc.main.id

  # Allow inbound HTTPS from the EC2 security group
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
    description = "Allow HTTPS from EC2 instances"
  }

  # Allow outbound HTTPS to the EC2 security group - optional, but recommended for clarity
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.ec2_sg.id]
    description = "Allow HTTPS to EC2 instances"
  }

  # Consider removing this rule if not strictly needed for specific endpoint access, and be more restrictive.
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }


  tags = {
    Name = "vpc-endpoint-sg-${random_string.random.result}"
  }
}