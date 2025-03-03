terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"  # Or even a later version, like "~> 5.30"
    }
  }
}

provider "aws" {
  region = var.aws_region
}