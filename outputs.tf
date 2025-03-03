output "load_balancer_url" {
  value       = aws_lb.main.dns_name
  description = "The DNS name of the Application Load Balancer (ALB). Use this to access the WordPress site directly if not using CloudFront."
}

output "database_endpoint" {
  value       = aws_db_instance.default.endpoint
  description = "The endpoint of the MySQL database (hostname:port).  This is sensitive information and should be treated accordingly."
  sensitive   = true
}

output "cloudfront_domain" {
  value       = aws_cloudfront_distribution.s3_distribution.domain_name
  description = "The domain name of the CloudFront distribution.  Use this to access the WordPress site via the CDN."
}

output "cloudfront_test_url" {
  value       = "https://${aws_cloudfront_distribution.s3_distribution.domain_name}"
  description = "Test URL for the CloudFront distribution (HTTPS).  Access the WordPress site through CloudFront using this URL."
}

output "loadbalancer_test_url" {
  value       = "http://${aws_lb.main.dns_name}"
  description = "Test URL for the Load Balancer (HTTP).  This will redirect to HTTPS.  Useful for testing the ALB directly."
}

output "loadbalancer_https_test_url" {
  value       = "https://${aws_lb.main.dns_name}"
  description = "Test URL for the Load Balancer (HTTPS).  Access the WordPress site directly through the ALB using this URL."
}

output "custom_domain_name" {
  value       = var.domain_name
  description = "The custom domain name used for the WordPress site. This is the domain you configured in Route 53."
}

output "vpc_id" {
  value = aws_vpc.main.id
  description = "The ID of the VPC."
}

output "private_subnet_ids" {
  value = [aws_subnet.private_subnet_a.id, aws_subnet.private_subnet_b.id]
  description = "List of private subnet IDs."
}

output "public_subnet_ids" {
  value = [aws_subnet.public_subnet_a.id, aws_subnet.public_subnet_b.id]
  description = "List of public subnet IDs."
}

output "asg_name" {
  description = "The name of the Auto Scaling Group"
  value       = aws_autoscaling_group.wordpress_asg.name
}

output "asg_arn" {
  description = "The ARN of the Auto Scaling Group"
  value       = aws_autoscaling_group.wordpress_asg.arn
}

output "wp_admin_login_url" {
  value       = "https://${var.domain_name}/wp-admin"
  description = "The WordPress admin login URL. Retrieve the username and password from AWS Secrets Manager."
}

output "wp_admin_secrets_arn" {
  value       = aws_secretsmanager_secret.wp_admin_creds.arn
  description = "The ARN of the Secrets Manager secret containing the WordPress admin credentials. Use this to retrieve the username and password securely."
}