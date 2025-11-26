variable "vpc_cidr" {
  type        = string
  default     = "10.0.0.0/16"
}

variable "subnet_cidr" {
  type        = string
  default     = "10.0.1.0/24"
}

variable "region" {
  type        = string
  default     = "us-east-1"
}

variable "ami_id" {
  type        = string
  default     = "ami-0fa3fe0fa7920f68e" 
}

variable "instance_type" {
  type        = string
  default     = "t2.micro"
}

variable "key_name" {
  type        = string
  default     = "ccem_sftp_key"
}