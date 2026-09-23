#Phase 1: Hardened Network Architecture

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

# 1. Primary VPC
resource "aws_vpc" "aegis_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "aegis-v4-vpc"
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

# 2. Subnet Tiering (Public, Private App, Isolated DB)
resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.aegis_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = { Name = "aegis-public-subnet-a" }
}

resource "aws_subnet" "private_app_subnet" {
  vpc_id            = aws_vpc.aegis_vpc.id
  cidr_block        = "10.0.10.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "aegis-private-app-subnet-a" }
}

resource "aws_subnet" "isolated_db_subnet" {
  vpc_id            = aws_vpc.aegis_vpc.id
  cidr_block        = "10.0.20.0/24"
  availability_zone = "${var.aws_region}a"

  tags = { Name = "aegis-isolated-db-subnet-a" }
}

# 3. Internet Gateway for Public Tier
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.aegis_vpc.id
  tags   = { Name = "aegis-igw" }
}

# 4. Route Tables
resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.aegis_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = { Name = "aegis-public-rt" }
}

resource "aws_route_table_association" "public_assoc" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.aegis_vpc.id
  tags   = { Name = "aegis-private-rt" }
}

resource "aws_route_table_association" "private_assoc" {
  subnet_id      = aws_subnet.private_app_subnet.id
  route_table_id = aws_route_table.private_rt.id
}

# Note: Isolated DB Subnet intentionally has NO Route Table Association for internet egress.

# 5. Cost Optimization: Free S3 VPC Gateway Endpoint
resource "aws_vpc_endpoint" "s3_endpoint" {
  vpc_id            = aws_vpc.aegis_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"

  route_table_ids = [
    aws_route_table.public_rt.id,
    aws_route_table.private_rt.id
  ]

  tags = { Name = "aegis-s3-gateway-endpoint" }
}

# 6. Strict Security Group Chaining (Cycle-Free)

# ALB Security Group (Public Ingress)
resource "aws_security_group" "alb_sg" {
  name        = "aegis-alb-sg"
  description = "Allow inbound HTTPS to ALB"
  vpc_id      = aws_vpc.aegis_vpc.id

  ingress {
    description = "Allow HTTPS from Internet"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # tfsec:ignore:aws-vpc-no-public-ingress-sgr
  }

  tags = { Name = "aegis-alb-sg" }
}

# App Tier Security Group (Restricted Ingress)
resource "aws_security_group" "app_sg" {
  name        = "aegis-app-sg"
  description = "Allow inbound traffic strictly from ALB SG"
  vpc_id      = aws_vpc.aegis_vpc.id

  ingress {
    description     = "HTTP from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  egress {
    description = "Allow outbound HTTPS strictly within VPC CIDR"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.aegis_vpc.cidr_block]
  }

  tags = { Name = "aegis-app-sg" }
}

# Separate Egress Rule to Break the Dependency Cycle
resource "aws_security_group_rule" "alb_to_app_egress" {
  type                     = "egress"
  from_port                = 8080
  to_port                  = 8080
  protocol                 = "tcp"
  security_group_id        = aws_security_group.alb_sg.id
  source_security_group_id = aws_security_group.app_sg.id
  description              = "Allow ALB outbound to App SG on port 8080"
}

# Air-Gapped DB Security Group
resource "aws_security_group" "db_sg" {
  name        = "aegis-db-sg"
  description = "Allow PostgreSQL inbound strictly from App SG"
  vpc_id      = aws_vpc.aegis_vpc.id

  ingress {
    description     = "PostgreSQL from App Tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_sg.id]
  }

  tags = { Name = "aegis-db-sg" }
}
