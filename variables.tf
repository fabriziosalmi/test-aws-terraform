variable "aws_region" {
  type        = string
  default     = "eu-south-1"
  description = "The AWS region to deploy to."
}

variable "ami_id" {
  type        = string
  default     = "ami-00e3619281c3422e2" # <------ CHECK IF THIS IS VALID!
  description = "The AMI ID to use for the EC2 instances (Amazon Linux 2). **Verify this AMI ID is valid in your region! AMI IDs are region-specific.** CHECK THIS VALUE!"
}

variable "instance_type" {
  type        = string
  default     = "t3.micro"
  description = "The EC2 instance type. Consider larger instance types for production."
}

variable "key_name" {
  type        = string
  default     = ""
  description = "The name of the SSH key pair to use for EC2 instances (optional). Leave empty if you don't need SSH access."
}

variable "db_name" {
  type        = string
  default     = "wordpressdb"
  description = "The name of the MySQL database."
}

variable "db_user" {
  type        = string
  default     = "wordpressuser"
  description = "The username for the MySQL database."
}

variable "db_password" {
  type        = string
  description = "Password for the RDS database.  This value will be automatically generated and stored in AWS Secrets Manager."
  sensitive   = true
}

variable "desired_capacity" {
  type        = number
  default     = 2
  description = "The desired number of EC2 instances in the Auto Scaling Group."
}

variable "max_size" {
  type        = number
  default     = 4
  description = "The maximum number of EC2 instances in the Auto Scaling Group."
}

variable "min_size" {
  type        = number
  default     = 1
  description = "The minimum number of EC2 instances in the Auto Scaling Group."
}

variable "db_instance_type" {
  type        = string
  default     = "db.t3.medium"
  description = "Database instance type. Consider larger instance types for production."
}

variable "domain_name" {
  type        = string
  default     = "wordpress.aws.italiadns.net"
  description = "The full subdomain for your WordPress site. This must be a registered domain in Route 53 and properly delegated to AWS name servers."
}

variable "web_acl_arn" {
  type        = string
  default     = ""
  description = "The ARN of the AWS WAFv2 Web ACL (optional)."
}

variable "default_instance_warmup" {
  type        = number
  default     = 300
  description = "Time (in seconds) until the EC2 instance is considered ready after launch for Auto Scaling Group health checks."
}

variable "estimated_instance_warmup" {
  type        = number
  default     = 300
  description = "Estimated time (in seconds) until the EC2 instance is warmed up for CloudWatch Alarms (optional)."
}

variable "allowed_inbound_cidr_blocks" {
  type        = list(string)
  # Replace with your actual IP address or CIDR block!
  default     = ["0.0.0.0/0"]  # <--- CHANGE THIS! Restrict access!
  description = "List of CIDR blocks allowed to access the ALB (HTTP/HTTPS).  **SHOULD BE RESTRICTED!**  Consider restricting to your IP address for testing, then to a more specific range for production."
}

variable "db_allocated_storage" {
  type        = number
  default     = 20
  description = "The allocated storage for the RDS instance (in GB)."
}

variable "db_skip_final_snapshot" {
  type        = bool
  default     = true
  description = "Whether to skip the final snapshot when deleting the RDS instance.  Set to `false` for production to prevent data loss."
}

variable "db_backup_retention_period" {
  type        = number
  default     = 7
  description = "The number of days to retain backups for the RDS instance."
}

variable "db_performance_insights_enabled" {
  type        = bool
  default     = true
  description = "Whether to enable Performance Insights for the RDS instance."
}

variable "db_performance_insights_retention_period" {
  type        = number
  default     = 7
  description = "The retention period (in days) for Performance Insights data."
}

variable "db_monitoring_interval" {
  type        = number
  default     = 30
  description = "The interval (in seconds) for RDS Enhanced Monitoring. Valid values: 0 (disabled), 10, 30, or 60."
}

variable "wp_admin_username" {
  type        = string
  default     = "admin"
  description = "The username for the WordPress administrator account. This value will be stored in AWS Secrets Manager."
}

variable "wp_admin_email" {
  type        = string
  default     = "fabrizio.salmi@gmail.com" # Make sure this is a valid email address
  description = "The email address for the WordPress administrator account. This value will be stored in AWS Secrets Manager."
}

variable "wp_admin_password" {
  type        = string
  sensitive   = true
  description = "The password for the WordPress administrator account.  This value will be automatically generated and stored in AWS Secrets Manager."
}

# Example terraform variable definition for credentials in JSON format
variable "db_creds" {
  type        = string
  description = "JSON string containing database credentials (dbname, username, password, host)"
  default     = ""
  sensitive   = true
}